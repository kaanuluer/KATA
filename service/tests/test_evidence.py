# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""External evidence verifier. Synthetic keys only. No vendor directory is contacted."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

import pytest
from fastapi.testclient import TestClient

from kata_intent import Actor, Agreement, generate_keypair, private_key_from_seed

from kata_service.asgi import create_app
from kata_service.bureau import BureauService, MemoryRepo
from kata_service.bureau_pg import _MIGRATIONS, _split_sql, migration_sql
from kata_service.evidence.jwks import FetchFailed, fetch_public_https, read_http_response
from kata_service.evidence.schema import EvidenceSchemaError, parse_evidence, payload_hash
from kata_service.evidence.ssrf import DirectoryRejected, assert_public_https
from kata_service.evidence.store import MemoryEvidenceStore, PostgresEvidenceStore
from kata_service.evidence.vectors import load_vectors, run_vector
from kata_service.evidence.verifier import verifier_for
from kata_service.settings import Settings, settings_from_env
from kata_service.store import MemoryStore

AT = "2026-10-04T13:55:00Z"
EXPIRY = "2026-12-31T23:59:59Z"
NOW = datetime(2026, 11, 13, 12, 0, tzinfo=timezone.utc)
DIRECTORY = "https://keys.example/jwks.json"
PENDING = _MIGRATIONS / "pending" / "021_external_evidence.sql"
PUBLIC = lambda host: ["8.8.8.8"]  # noqa: E731 — test resolver, never dialed


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _settings(**overrides) -> Settings:
    base = dict(
        database_url=None,
        schema_url=None,
        log_signing_seed=hashlib.sha256(b"evidence-test-log").digest(),
        push_notifier_jwk=None,
        append_token=None,
        published_keys=(),
        fx_source_url="https://fx.test",
        admin_token="admin-test-token",
        rate_limit_per_minute=30,
        report_daily_cap=5,
    )
    base.update(overrides)
    return Settings(**base)


def _client(**overrides) -> TestClient:
    return TestClient(create_app(_settings(**overrides), MemoryStore()))


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _org(client: TestClient, name: str, org_type: str) -> dict:
    response = client.post("/v1/orgs", headers=_auth("admin-test-token"), json={"name": name, "org_type": org_type})
    assert response.status_code == 200, response.text
    return response.json()


def _key(client: TestClient, org_id: str) -> str:
    response = client.post(f"/v1/orgs/{org_id}/keys", headers=_auth("admin-test-token"), json={"name": "primary"})
    assert response.status_code == 200, response.text
    return response.json()["token"]


def _register(client: TestClient, operator_key: str) -> None:
    _principal, agent = _agent_keys()
    response = client.post(
        "/v1/agents",
        headers=_auth(operator_key),
        json={
            "agent_id": "shopper-01",
            "principal_id": "prn_person",
            "public_key": agent.public.to_jwk(),
            "verification_level": "operator_verified",
        },
    )
    assert response.status_code == 200, response.text


def _agent_keys():
    return (
        private_key_from_seed(hashlib.sha256(b"evidence-principal").digest()),
        private_key_from_seed(hashlib.sha256(b"evidence-agent").digest()),
    )


def _agreement():
    principal, agent = _agent_keys()
    agreement = Agreement.propose(
        agreement_id="agr_evidence",
        principal={"display_name": "A Principal", "id": "prn_person", "type": "human"},
        agent={"agent_id": "shopper-01"},
        agent_public_key=agent.public,
        intent={
            "allowed_actions": ["purchase"],
            "currency": "CAD",
            "intent_id": "int_laptop",
            "maximum_amount": 1500,
            "purpose": "purchase",
            "time_limit": EXPIRY,
            "version": 1,
        },
        limits={"cumulative_maximum": 2000},
        parent_limits={"cumulative_maximum": 2000, "currency": "CAD", "maximum_amount": 1500},
        actor=Actor("agent", "shopper-01"),
        at=AT,
        expires_at=EXPIRY,
    )
    agreement.accept(principal, AT, confirmed_text=agreement.rendering_preview())
    return agreement


def _action(action_id: str = "act_evidence") -> dict:
    return {
        "action_id": action_id,
        "action_type": "purchase",
        "amount": 10,
        "context": {"merchant": "techstore.example"},
        "currency": "CAD",
        "item": "Laptop",
        "parameters": {"merchant": "techstore.example", "quantity": 1},
        "proposed_at": AT,
    }


class ScriptedFetch:
    def __init__(self, bodies: list[bytes] | None = None, error: BaseException | None = None) -> None:
        self.bodies = list(bodies or [])
        self.error = error
        self.calls = 0
        self.urls: list[str] = []

    def __call__(self, url: str, timeout: float) -> bytes:
        del timeout
        self.calls += 1
        self.urls.append(url)
        if self.error is not None:
            raise self.error
        if not self.bodies:
            raise FetchFailed("jwks fetch failed")
        return self.bodies.pop(0)


def _jwk(private, kid: str) -> dict:
    document = private.public.to_jwk()
    document["kid"] = kid
    document["alg"] = private.algorithm
    document["use"] = "sig"
    return document


def _jwks(*keys: dict) -> bytes:
    return json.dumps({"keys": list(keys)}).encode("utf-8")


def _token(private, payload: dict, *, kid: str, alg: str | None = None) -> str:
    header = {"alg": alg or private.algorithm, "kid": kid, "typ": "JWT"}
    encoded_header = _b64(json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    encoded_payload = _b64(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    signature = private.sign(f"{encoded_header}.{encoded_payload}".encode("ascii"))
    return f"{encoded_header}.{encoded_payload}.{_b64(signature)}"


def _payload(now: datetime, **extra) -> dict:
    shift = extra.pop("exp_shift", 600)
    body = {
        "exp": int(now.timestamp()) + shift,
        "iat": int(now.timestamp()),
        "iss": "https://issuer.example",
        "jti": extra.pop("jti", "jti-1"),
        "sub": "agent-synthetic",
    }
    body.update(extra)
    return body


def _verify(store, private, payload, *, kid="kid-1", alg=None, fetch=None, directory=DIRECTORY, **deps):
    token = _token(private, payload, kid=kid, alg=alg)
    if fetch is None:
        fetch = ScriptedFetch([_jwks(_jwk(private, kid))])
    verifier = verifier_for(
        "jwt",
        store,
        fetch=fetch,
        resolve=deps.pop("resolve", PUBLIC),
        **deps,
    )
    evidence = verifier.verify({"source": "jwt", "token": token, "directory": directory}, now=NOW)
    return evidence, token, fetch


def _database_url() -> str:
    url = os.environ.get("GAB_TEST_DATABASE_URL")
    if not url:
        if os.environ.get("GITHUB_ACTIONS"):
            pytest.fail("GAB_TEST_DATABASE_URL is required in CI")
        pytest.skip("GAB_TEST_DATABASE_URL is not set")
    host = urlparse(url).hostname
    if host not in {"localhost", "127.0.0.1"}:
        pytest.fail("GAB_TEST_DATABASE_URL must point at localhost")
    return url


@pytest.fixture(params=["memory", "postgres"])
def store(request):
    if request.param == "memory":
        return MemoryEvidenceStore()
    url = _database_url()
    import psycopg

    schema = "evidence_test"
    with psycopg.connect(url, autocommit=True) as conn:
        conn.execute(f"DROP SCHEMA IF EXISTS {schema} CASCADE")
        conn.execute(f"CREATE SCHEMA {schema}")
        conn.execute(f"SET search_path TO {schema}")
        for statement in _split_sql(PENDING.read_text(encoding="utf-8")):
            conn.execute(statement)
    return PostgresEvidenceStore(url, schema=schema)


def test_flag_defaults_off_and_breach_tools_stay_off():
    settings = settings_from_env({})
    assert settings.evidence_verifier is False
    assert settings.breach_tools is False
    assert settings_from_env({"GAB_EVIDENCE_VERIFIER": "1"}).evidence_verifier is True
    assert settings_from_env({"GAB_EVIDENCE_VERIFIER": "0"}).evidence_verifier is False
    assert BureauService(MemoryRepo()).evidence_verifier is False


def test_pending_migration_is_not_on_the_boot_path():
    assert "gab_external_evidence" not in migration_sql()
    assert "021_external_evidence.sql" not in {path.name for path in _MIGRATIONS.glob("*.sql")}
    text = PENDING.read_text(encoding="utf-8")
    assert "CREATE TABLE IF NOT EXISTS gab_external_evidence" in text
    assert "CREATE TABLE IF NOT EXISTS gab_evidence_keys" in text
    assert "CREATE TABLE IF NOT EXISTS gab_evidence_nonces" in text
    assert "valid" in text and "invalid" in text and "unverifiable" in text


def test_schema_rejects_a_decision_result():
    with pytest.raises(EvidenceSchemaError):
        parse_evidence(
            {
                "source": "jwt",
                "issuer": "https://issuer.example",
                "subject": "agent-synthetic",
                "claims": {},
                "verified_at": "2026-11-13T12:00:00Z",
                "key_id": "kid-1",
                "result": "ALLOW",
                "reason": "ok",
                "payload_hash": "ab" * 32,
            }
        )


def test_valid_ed25519_and_es256_signatures(store):
    for algorithm in ("EdDSA", "ES256"):
        private = generate_keypair(algorithm)
        kid = f"kid-{algorithm}"
        directory = f"https://{algorithm.lower()}.example/jwks.json"
        evidence, token, fetch = _verify(
            store,
            private,
            _payload(NOW, jti=f"jti-{algorithm}"),
            kid=kid,
            directory=directory,
        )
        assert evidence["result"] == "valid"
        assert evidence["reason"] == "ok"
        assert evidence["source"] == "jwt"
        assert evidence["key_id"] == kid
        assert evidence["issuer"] == "https://issuer.example"
        assert evidence["subject"] == "agent-synthetic"
        assert "kata_decision" not in evidence
        assert "verdict" not in evidence
        segment = token.split(".")[1]
        payload_bytes = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
        assert evidence["payload_hash"] == payload_hash(payload_bytes)
        assert token not in json.dumps(evidence)
        assert fetch.calls == 1
        again, _token_again, fetch = _verify(
            store,
            private,
            _payload(NOW, jti=f"jti-{algorithm}-2"),
            kid=kid,
            directory=directory,
            fetch=fetch,
        )
        assert again["result"] == "valid"
        assert fetch.calls == 1


def test_wrong_signature_unknown_kid_and_expiry(store):
    private = generate_keypair("EdDSA")
    evidence, token, fetch = _verify(store, private, _payload(NOW, jti="jti-bad"))
    head, payload, signature = token.split(".")
    raw = bytearray(base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4)))
    raw[-1] ^= 0x01
    flipped = _b64(bytes(raw))
    bad = verifier_for("jwt", store, fetch=fetch, resolve=PUBLIC)
    failed = bad.verify({"token": f"{head}.{payload}.{flipped}", "directory": DIRECTORY}, now=NOW)
    assert failed["result"] == "invalid"
    assert failed["reason"] == "signature"
    assert fetch.calls == 1

    missing = ScriptedFetch([_jwks(_jwk(private, "kid-other"))])
    unknown = verifier_for("jwt", store, fetch=missing, resolve=PUBLIC)
    result = unknown.verify(
        {
            "token": _token(private, _payload(NOW, jti="jti-unknown"), kid="kid-1"),
            "directory": "https://unknown.example/jwks.json",
        },
        now=NOW,
    )
    assert result["result"] == "invalid"
    assert result["reason"] == "unknown_kid"
    assert missing.calls == 1

    expired_fetch = ScriptedFetch([_jwks(_jwk(private, "kid-1"))])
    expired = verifier_for("jwt", store, fetch=expired_fetch, resolve=PUBLIC).verify(
        {
            "token": _token(private, _payload(NOW, jti="jti-expired", exp_shift=-61), kid="kid-1"),
            "directory": DIRECTORY,
        },
        now=NOW,
    )
    assert expired["result"] == "invalid"
    assert expired["reason"] == "expired"
    assert expired_fetch.calls == 0


def test_alg_none_and_alg_confusion_do_not_fetch(store):
    private = generate_keypair("ES256")
    fetch = ScriptedFetch([_jwks(_jwk(private, "kid-1"))])
    verifier = verifier_for("jwt", store, fetch=fetch, resolve=PUBLIC)
    header = _b64(json.dumps({"alg": "none", "kid": "kid-1", "typ": "JWT"}, separators=(",", ":")).encode())
    body = _b64(json.dumps(_payload(NOW, jti="jti-none"), separators=(",", ":"), sort_keys=True).encode())
    none = verifier.verify({"token": f"{header}.{body}.", "directory": DIRECTORY}, now=NOW)
    assert none["result"] == "invalid"
    assert none["reason"] == "alg_rejected"

    mixed = _b64(json.dumps({"alg": "None", "kid": "kid-1"}, separators=(",", ":")).encode())
    mixed_result = verifier.verify({"token": f"{mixed}.{body}.x", "directory": DIRECTORY}, now=NOW)
    assert mixed_result["reason"] == "alg_rejected"

    import hmac

    mac_header = _b64(json.dumps({"alg": "HS256", "kid": "kid-1", "typ": "JWT"}, separators=(",", ":")).encode())
    mac = _b64(hmac.new(private.public.raw, f"{mac_header}.{body}".encode("ascii"), hashlib.sha256).digest())
    confused = verifier.verify({"token": f"{mac_header}.{body}.{mac}", "directory": DIRECTORY}, now=NOW)
    assert confused["result"] == "invalid"
    assert confused["reason"] == "alg_rejected"

    other = generate_keypair("EdDSA")
    mismatch_fetch = ScriptedFetch([_jwks(_jwk(other, "kid-1"))])
    mismatch = verifier_for("jwt", store, fetch=mismatch_fetch, resolve=PUBLIC).verify(
        {
            "token": _token(private, _payload(NOW, jti="jti-mix"), kid="kid-1", alg="ES256"),
            "directory": DIRECTORY,
        },
        now=NOW,
    )
    assert mismatch["result"] == "invalid"
    assert mismatch["reason"] == "alg_mismatch"
    assert fetch.calls == 0


def test_replay_and_clock_skew(store):
    private = generate_keypair("EdDSA")
    fetch = ScriptedFetch([_jwks(_jwk(private, "kid-1"))])
    verifier = verifier_for("jwt", store, fetch=fetch, resolve=PUBLIC)
    token = _token(private, _payload(NOW, jti="jti-replay"), kid="kid-1")
    material = {"token": token, "directory": DIRECTORY}
    first = verifier.verify(material, now=NOW)
    second = verifier.verify(material, now=NOW)
    assert first["result"] == "valid"
    assert second["result"] == "invalid"
    assert second["reason"] == "replay"

    within = verifier.verify(
        {"token": _token(private, _payload(NOW, jti="jti-skew", exp_shift=-60), kid="kid-1"), "directory": DIRECTORY},
        now=NOW,
    )
    assert within["result"] == "valid"
    outside = verifier.verify(
        {"token": _token(private, _payload(NOW, jti="jti-outside", exp_shift=-61), kid="kid-1"), "directory": DIRECTORY},
        now=NOW,
    )
    assert outside["reason"] == "expired"

    future = verifier.verify(
        {
            "token": _token(private, _payload(NOW, jti="jti-future", iat=int(NOW.timestamp()) + 61), kid="kid-1"),
            "directory": DIRECTORY,
        },
        now=NOW,
    )
    assert future["reason"] == "future_iat"
    almost = verifier.verify(
        {
            "token": _token(private, _payload(NOW, jti="jti-almost", iat=int(NOW.timestamp()) + 60), kid="kid-1"),
            "directory": DIRECTORY,
        },
        now=NOW,
    )
    assert almost["result"] == "valid"
    waiting = verifier.verify(
        {
            "token": _token(private, _payload(NOW, jti="jti-nbf", nbf=int(NOW.timestamp()) + 61), kid="kid-1"),
            "directory": DIRECTORY,
        },
        now=NOW,
    )
    assert waiting["reason"] == "not_yet_valid"


def test_jwks_fetch_failure_is_unverifiable(store):
    private = generate_keypair("EdDSA")
    fetch = ScriptedFetch(error=OSError("directory unavailable"))
    evidence, _issued, fetch = _verify(store, private, _payload(NOW, jti="jti-down"), fetch=fetch)
    assert evidence["result"] == "unverifiable"
    assert evidence["reason"] == "jwks_fetch_failed"
    assert fetch.calls == 1
    huge = ScriptedFetch([b"{" + b" " * 70000])
    oversized = verifier_for("jwt", store, fetch=huge, resolve=PUBLIC, max_bytes=1024).verify(
        {"token": _token(private, _payload(NOW, jti="jti-huge"), kid="kid-1"), "directory": DIRECTORY},
        now=NOW,
    )
    assert oversized["result"] == "unverifiable"
    assert oversized["reason"] == "jwks_fetch_failed"


def test_ssrf_targets_are_not_fetched(store):
    private = generate_keypair("EdDSA")
    token = _token(private, _payload(NOW, jti="jti-ssrf"), kid="kid-1")
    blocked = [
        "http://keys.example/jwks.json",
        "https://127.0.0.1/jwks.json",
        "https://127.0.0.2/jwks.json",
        "https://10.1.2.3/jwks.json",
        "https://192.168.1.9/jwks.json",
        "https://172.16.0.4/jwks.json",
        "https://169.254.169.254/latest",
        "https://[::1]/jwks.json",
        "https://[fe80::1]/jwks.json",
        "https://localhost/jwks.json",
        "https://keys.localhost/jwks.json",
        "https://metadata.google.internal/jwks.json",
        "https://user:pass@8.8.8.8/jwks.json",
        "https://2130706433/jwks.json",
    ]
    for directory in blocked:
        fetch = ScriptedFetch([_jwks(_jwk(private, "kid-1"))])
        evidence = verifier_for("jwt", store, fetch=fetch, resolve=PUBLIC).verify(
            {"token": token, "directory": directory},
            now=NOW,
        )
        assert evidence["result"] == "unverifiable", directory
        assert evidence["reason"] == "directory_url_rejected", directory
        assert fetch.calls == 0, directory
        assert directory not in json.dumps(evidence)

    fetch = ScriptedFetch([_jwks(_jwk(private, "kid-1"))])
    rebound = verifier_for("jwt", store, fetch=fetch, resolve=lambda host: ["127.0.0.1"]).verify(
        {"token": token, "directory": "https://rebind.example/jwks.json"},
        now=NOW,
    )
    assert rebound["reason"] == "directory_url_rejected"
    assert fetch.calls == 0
    with pytest.raises(DirectoryRejected):
        assert_public_https("https://10.0.0.8/jwks.json", resolve=PUBLIC)


def test_kid_rotation_refreshes_once(store):
    first = generate_keypair("EdDSA")
    second = generate_keypair("EdDSA")
    fetch = ScriptedFetch([_jwks(_jwk(first, "kid-old")), _jwks(_jwk(second, "kid-new"))])
    verifier = verifier_for("jwt", store, fetch=fetch, resolve=PUBLIC, ttl_seconds=60)
    old = verifier.verify(
        {"token": _token(first, _payload(NOW, jti="jti-old"), kid="kid-old"), "directory": DIRECTORY},
        now=NOW,
    )
    assert old["result"] == "valid"
    rotated = verifier.verify(
        {"token": _token(second, _payload(NOW, jti="jti-new"), kid="kid-new"), "directory": DIRECTORY},
        now=NOW,
    )
    assert rotated["result"] == "valid"
    assert rotated["key_id"] == "kid-new"
    assert fetch.calls == 2


def test_cache_size_limit(store):
    from kata_service.evidence.jwks import directory_hash

    first = generate_keypair("EdDSA")
    second = generate_keypair("EdDSA")
    later = NOW + timedelta(seconds=5)
    limited = ScriptedFetch([_jwks(_jwk(first, "kid-a")), _jwks(_jwk(second, "kid-b"))])
    small = verifier_for("jwt", store, fetch=limited, resolve=PUBLIC, max_entries=1)
    assert small.verify(
        {"token": _token(first, _payload(NOW, jti="jti-a"), kid="kid-a"), "directory": "https://a.example/jwks.json"},
        now=NOW,
    )["result"] == "valid"
    assert small.verify(
        {"token": _token(second, _payload(NOW, jti="jti-b"), kid="kid-b"), "directory": "https://b.example/jwks.json"},
        now=later,
    )["result"] == "valid"
    assert store.read_keys(directory_hash("https://a.example/jwks.json"), later) == []
    assert [item["kid"] for item in store.read_keys(directory_hash("https://b.example/jwks.json"), later)] == ["kid-b"]


def test_sensitive_claim_is_not_stored(store):
    private = generate_keypair("EdDSA")
    evidence, _token, fetch = _verify(
        store,
        private,
        _payload(NOW, jti="jti-secret", national_id="123-45-6789"),
    )
    assert evidence["result"] == "invalid"
    assert evidence["reason"] == "sensitive_claim"
    assert evidence["claims"] == {}
    assert "123-45-6789" not in json.dumps(evidence)
    assert fetch.calls == 0


def test_synthetic_vectors_and_generated_jwt_vectors(store, tmp_path: Path):
    for vector in load_vectors():
        results = run_vector(vector, MemoryEvidenceStore())
        last = results[-1]
        for key, value in vector["expect"].items():
            assert last[key] == value
        if vector["name"] == "synthetic-replay":
            assert results[0]["result"] == "valid"
            assert results[1]["reason"] == "replay"

    private = generate_keypair("EdDSA")
    es256 = generate_keypair("ES256")
    generated = {
        "version": 1,
        "vectors": [
            {
                "name": "generated-ed25519",
                "source": "jwt",
                "now": "2026-11-13T12:00:00Z",
                "jwks": {"keys": [_jwk(private, "kid-ed")]},
                "material": {
                    "directory": DIRECTORY,
                    "token": _token(private, _payload(NOW, jti="jti-vector-ed"), kid="kid-ed"),
                },
                "expect": {"result": "valid", "reason": "ok", "key_id": "kid-ed"},
            },
            {
                "name": "generated-es256",
                "source": "jwt",
                "now": "2026-11-13T12:00:00Z",
                "jwks": {"keys": [_jwk(es256, "kid-ec")]},
                "material": {
                    "directory": DIRECTORY,
                    "token": _token(es256, _payload(NOW, jti="jti-vector-ec"), kid="kid-ec"),
                },
                "expect": {"result": "valid", "reason": "ok", "key_id": "kid-ec"},
            },
        ],
    }
    path = tmp_path / "generated.json"
    path.write_text(json.dumps(generated), encoding="utf-8")
    for vector in load_vectors(path):
        fetch = ScriptedFetch([json.dumps(vector["jwks"]).encode("utf-8")])
        results = run_vector(vector, store, fetch=fetch, resolve=PUBLIC)
        for key, value in vector["expect"].items():
            assert results[-1][key] == value


def test_http_response_parser_refuses_redirects_and_oversize_bodies():
    def serve(raw: bytes):
        chunks = [raw]

        def recv(size: int) -> bytes:
            del size
            if not chunks:
                return b""
            return chunks.pop(0)

        return recv

    body = b'{"keys":[]}'
    ok = b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
    assert read_http_response(serve(ok), limit=100) == body
    redirect = b"HTTP/1.1 302 Found\r\nLocation: https://127.0.0.1/\r\nContent-Length: 0\r\n\r\n"
    with pytest.raises(FetchFailed):
        read_http_response(serve(redirect), limit=100)
    huge = b"HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\n" + b"x" * 50
    with pytest.raises(FetchFailed):
        read_http_response(serve(huge), limit=10)


def test_default_fetch_pins_the_checked_address(monkeypatch):
    dialed: list[str] = []

    def connect(address, timeout):
        del timeout
        dialed.append(address[0])
        raise OSError("stopped before a request")

    monkeypatch.setattr("kata_service.evidence.jwks.socket.create_connection", connect)
    with pytest.raises(FetchFailed):
        fetch_public_https("https://keys.example/jwks.json", 1, resolve=lambda host: ["8.8.8.8", "1.1.1.1"])
    assert dialed == ["8.8.8.8"]
    dialed.clear()
    with pytest.raises(DirectoryRejected):
        fetch_public_https("https://keys.example/jwks.json", 1, resolve=lambda host: ["10.0.0.4"])
    assert dialed == []


def _ready(client: TestClient, operator_key: str | None = None) -> str:
    operator = _org(client, "Harbor Agents", "agent_operator")
    key = operator_key or _key(client, operator["org_id"])
    _register(client, key)
    stored = client.post(
        "/v1/agents/shopper-01/intents",
        headers={**_auth(key), "Content-Type": "application/json"},
        content=_agreement().to_json(),
    )
    assert stored.status_code == 200, stored.text
    return key


def test_flag_off_does_not_change_verify_bytes():
    off = _client()
    key = _ready(off)
    plain = {"agent_id": "shopper-01", "action": _action("act_plain")}
    extra = {
        "agent_id": "shopper-01",
        "action": _action("act_extra"),
        "external_evidence": {
            "source": "synthetic",
            "issuer": "https://issuer.example",
            "subject": "agent-synthetic",
            "key_id": "kid-synthetic",
            "nonce": "nonce-http",
            "claims": {"purpose": "purchase"},
            "accept": True,
        },
    }
    first = off.post("/v1/verify", headers=_auth(key), json=plain)
    second = off.post("/v1/verify", headers=_auth(key), json=extra)
    assert first.status_code == 200
    assert first.content == second.content.replace(b"act_extra", b"act_plain")
    assert first.json()["verdict"] == "ALLOW"
    assert first.json()["kata_decision"] == "ALLOW"
    assert "external_evidence" not in first.json()


def test_evidence_does_not_decide():
    client = _client(evidence_verifier=True)
    key = _ready(client)
    body = {
        "agent_id": "shopper-01",
        "action": _action("act_flag"),
        "external_evidence": {
            "source": "synthetic",
            "issuer": "https://issuer.example",
            "subject": "agent-synthetic",
            "key_id": "kid-synthetic",
            "nonce": "nonce-http",
            "claims": {"purpose": "purchase"},
            "accept": False,
        },
    }
    off = _client()
    off_key = _ready(off)
    baseline = off.post("/v1/verify", headers=_auth(off_key), json={"agent_id": "shopper-01", "action": _action("act_flag")})
    recorded = client.post("/v1/verify", headers=_auth(key), json=body)
    assert recorded.status_code == 200
    assert recorded.content == baseline.content
    assert recorded.json()["verdict"] == "ALLOW"
    assert recorded.json()["kata_decision"] == "ALLOW"
    store = client.app.state.bureau._evidence_store
    rows = store.list_evidence()
    assert len(rows) == 1
    row = rows[0]
    assert row["evidence"]["result"] == "invalid"
    assert row["evidence"]["reason"] == "signature"
    assert row["kata_decision"] == "ALLOW"
    assert row["evidence"]["result"] != row["kata_decision"]
    assert row["audit_id"].startswith("aud_")
    assert "decision" not in row["evidence"]
    failed = client.post(
        "/v1/verify",
        headers=_auth(key),
        json={
            "agent_id": "shopper-01",
            "action": _action("act_again"),
            "external_evidence": {"source": "not-a-protocol", "token": "nope"},
        },
    )
    assert failed.json()["verdict"] == "ALLOW"
    assert store.list_evidence()[-1]["evidence"]["result"] == "unverifiable"
    assert store.list_evidence()[-1]["evidence"]["reason"] == "unsupported_verifier"


def test_nonce_expires_and_can_be_used_again(store):
    moment = NOW
    assert store.consume_nonce("https://issuer.example", "once", now=moment, expires_at=moment + timedelta(seconds=30))
    assert store.consume_nonce("https://issuer.example", "once", now=moment, expires_at=moment + timedelta(seconds=30)) is False
    later = moment + timedelta(seconds=31)
    assert store.consume_nonce("https://issuer.example", "once", now=later, expires_at=later + timedelta(seconds=30))
