# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: Apache-2.0
"""Handler tests. They use the in-memory store and do not open a network connection."""

from __future__ import annotations

import base64
import json

import pytest
from fastapi.testclient import TestClient

from kata_intent import Actor, Agreement, generate_keypair, private_key_from_seed
from kata_intent.revocation import TransparencyLog, sign_revocation_push, verify_inclusion, verify_tree_head

from kata_service.asgi import create_app
from kata_service.fx import FrankfurterFx
from kata_service.settings import settings_from_env
from kata_service.store import MemoryStore

AT = "2026-10-04T13:55:00Z"
EXPIRY = "2026-10-10T23:59:59Z"


class CountingFx:
    def __init__(self) -> None:
        self.calls = 0

    def fetch(self, currency: str, day: str, reference_currency: str) -> str | None:
        self.calls += 1
        if currency == "CAD" and reference_currency == "USD" and day == "2026-10-04":
            return "0.75"
        return None


def _settings(log_key, notifier):
    from kata_service.settings import Settings

    return Settings(
        database_url=None,
        schema_url=None,
        log_signing_seed=log_key.seed,
        push_notifier_jwk=notifier.public.to_jwk(),
        append_token="append-secret",
        published_keys=(),
        fx_source_url="https://fx.test",
    )


def _client(log_key, notifier, fx=None):
    return TestClient(create_app(_settings(log_key, notifier), MemoryStore(), fx or CountingFx()))


def _revocation(principal, agent):
    agreement = Agreement.propose(
        agreement_id="agr_service",
        principal={"display_name": "K. Uluer", "id": "usr_9182", "type": "human"},
        agent={"agent_id": "shopper-01"},
        agent_public_key=agent.public,
        intent={
            "allowed_actions": ["purchase"],
            "currency": "CAD",
            "intent_id": "int_9f31",
            "maximum_amount": 1500,
            "purpose": "purchase",
            "time_limit": EXPIRY,
            "version": 1,
        },
        actor=Actor("agent", "shopper-01"),
        at=AT,
        expires_at=EXPIRY,
    )
    agreement.accept(principal, AT, confirmed_text=agreement.rendering_preview())
    return agreement.revoke(principal, "2026-10-04T18:00:00Z")


def test_revocation_list_is_cached_for_five_minutes(log_key, notifier):
    client = _client(log_key, notifier)
    response = client.get("/v1/revocations")
    assert response.status_code == 200
    assert response.json() == {"revocations": []}
    assert response.headers["cache-control"] == "public, max-age=300"


def test_push_stores_a_signed_revocation_once(log_key, notifier, principal, agent):
    client = _client(log_key, notifier)
    notice = sign_revocation_push(_revocation(principal, agent), notifier, "2026-10-04T18:01:00Z")
    first = client.post("/v1/revocations/push", json=notice)
    assert first.status_code == 200
    assert first.json()["stored"] is True
    listed = client.get("/v1/revocations")
    assert listed.headers["cache-control"] == "public, max-age=300"
    assert listed.json()["revocations"][0]["agreement_id"] == "agr_service"
    again = client.post("/v1/revocations/push", json=notice)
    assert again.json()["stored"] is False
    assert client.get("/v1/log/head").json()["tree_size"] == 1

    rejected = client.post("/v1/revocations/push", json={"at": "2026-10-04T18:01:00Z", "kata_revocation_push": "1"})
    assert rejected.status_code == 401
    assert client.get("/v1/revocations").json()["revocations"].__len__() == 1


def test_log_append_proof_and_signed_head(log_key, notifier):
    client = _client(log_key, notifier)
    missing = client.post("/v1/log/entries", json={"kind": "agreement", "body": {"agreement_id": "agr_service"}})
    assert missing.status_code == 401
    wrong = client.post(
        "/v1/log/entries",
        json={"kind": "agreement", "body": {"agreement_id": "agr_service"}},
        headers={"Authorization": "Bearer other"},
    )
    assert wrong.status_code == 401

    appended = client.post(
        "/v1/log/entries",
        json={"kind": "agreement", "body": {"agreement_id": "agr_service"}},
        headers={"Authorization": "Bearer append-secret"},
    )
    assert appended.status_code == 200
    assert appended.json()["entry"]["sequence"] == 1
    second = client.post(
        "/v1/log/entries",
        json={"kind": "revocation", "body": {"agreement_id": "agr_service", "reason": "principal_request"}},
        headers={"Authorization": "Bearer append-secret"},
    )
    assert second.status_code == 200
    refused = client.post(
        "/v1/log/entries",
        json={"kind": "note", "body": {}},
        headers={"Authorization": "Bearer append-secret"},
    )
    assert refused.status_code == 400

    entry = client.get("/v1/log/entries/2")
    assert entry.status_code == 200
    assert client.get("/v1/log/entries/9").status_code == 404

    proof = client.get("/v1/log/entries/2/proof").json()
    assert verify_inclusion(proof["leaf"], proof["index"], proof["proof"], proof["root"])
    head = client.get("/v1/log/head").json()
    log = TransparencyLog()
    log.entries = [
        client.get("/v1/log/entries/1").json()["entry"],
        client.get("/v1/log/entries/2").json()["entry"],
    ]
    assert verify_tree_head(head, log_key.public, log)
    assert client.get("/v1/log/entries/3/proof").status_code == 404


def test_well_known_publishes_the_log_key_and_not_the_seed(log_key, notifier):
    from kata_service.settings import Settings

    extra = generate_keypair("EdDSA")
    settings = Settings(
        database_url=None,
        schema_url=None,
        log_signing_seed=log_key.seed,
        push_notifier_jwk=notifier.public.to_jwk(),
        append_token="append-secret",
        published_keys=({"public_key": extra.public.to_jwk()},),
        fx_source_url="https://fx.test",
    )
    client = TestClient(create_app(settings, MemoryStore(), CountingFx()))
    document = client.get("/.well-known/kata-keys.json")
    assert document.status_code == 200
    body = document.json()
    assert body["keys"][0]["public_key"] == log_key.public.to_jwk()
    assert body["keys"][1]["public_key"]["x"] == extra.public.to_jwk()["x"]
    for record in body["keys"]:
        assert "d" not in record["public_key"]


def test_security_txt_is_public_and_retired_hosts_are_absent():
    from kata_service.pages import repo_root
    from kata_service.settings import Settings

    client = TestClient(
        create_app(
            Settings(None, None, None, None, None, (), "https://fx.test"),
            MemoryStore(),
        )
    )
    note = client.get("/.well-known/security.txt")
    assert note.status_code == 200
    assert note.headers["content-type"].startswith("text/plain")
    assert note.text == (
        "Contact: mailto:info@globalagentbureau.com\n"
        "Expires: 2027-10-15T00:00:00.000Z\n"
        "Preferred-Languages: en\n"
        "Canonical: https://globalagentbureau.com/.well-known/security.txt\n"
    )
    banned = ("kata-service-omega.vercel.app", "www.globalagentbureau.com")
    for path in ("/", "/docs", "/history", "/simulation", "/portal", "/dashboard", "/docs/api"):
        page = client.get(path)
        assert page.status_code == 200
        for host in banned:
            assert host not in page.text
    root = repo_root()
    files = [root / "README.md", root / "service" / "README.md"]
    files.extend((root / "docs").rglob("*.md"))
    files.extend((root / "service" / "kata_service" / "static").rglob("*.html"))
    files.extend((root / "service" / "kata_service" / "static").rglob("*.js"))
    for item in files:
        text = item.read_text(encoding="utf-8")
        for host in banned:
            assert host not in text, f"{host} in {item.relative_to(root)}"


def test_fx_uses_the_fetcher_once_and_then_the_store(log_key, notifier):
    fx = CountingFx()
    client = _client(log_key, notifier, fx)
    first = client.get("/v1/fx", params={"currency": "CAD", "reference": "USD", "day": "2026-10-04"})
    second = client.get("/v1/fx", params={"currency": "CAD", "reference_currency": "USD", "day": "2026-10-04"})
    assert first.json()["rate"] == "0.75"
    assert second.json()["rate"] == "0.75"
    assert fx.calls == 1
    same = client.get("/v1/fx", params={"currency": "USD", "reference": "USD", "day": "2026-10-04"})
    assert same.json()["rate"] == "1"
    assert fx.calls == 1
    missing = client.get("/v1/fx", params={"currency": "EUR", "reference": "USD", "day": "2026-10-04"})
    assert missing.status_code == 404


def test_storage_and_signing_configuration_are_required():
    from kata_service.settings import Settings

    bare = TestClient(
        create_app(
            Settings(None, None, None, None, None, (), "https://fx.test"),
            store=None,
        )
    )
    assert bare.get("/v1/revocations").status_code == 503
    assert bare.get("/v1/fx", params={"currency": "CAD", "reference": "USD", "day": "2026-10-04"}).status_code == 503
    same = bare.get("/v1/fx", params={"currency": "USD", "reference": "USD"})
    assert same.status_code == 200
    assert same.json()["rate"] == "1"


def test_settings_accept_the_neon_url_and_reject_a_private_jwk():
    seed = generate_keypair("EdDSA")
    public = json.dumps(seed.public.to_jwk())
    parsed = settings_from_env(
        {
            "POSTGRES_URL": "postgresql://example",
            "KATA_LOG_SIGNING_SEED": base64.b64encode(seed.seed).decode(),
            "KATA_PUSH_NOTIFIER_JWK": public,
            "KATA_APPEND_TOKEN": "token",
        }
    )
    assert parsed.database_url == "postgresql://example"
    assert parsed.config_error is None
    assert parsed.log_key() is not None
    private = dict(seed.public.to_jwk())
    private["d"] = "c2VjcmV0"
    rejected = settings_from_env({"KATA_PUSH_NOTIFIER_JWK": json.dumps(private), "DATABASE_URL": "postgresql://example"})
    assert rejected.config_error


def test_frankfurter_parser_reads_the_reference_rate():
    def opener(url: str) -> str:
        assert url == "https://api.frankfurter.dev/v1/2026-10-04?from=CAD&to=USD"
        return '{"amount":1,"base":"CAD","date":"2026-10-04","rates":{"USD":0.75}}'

    fx = FrankfurterFx("https://api.frankfurter.dev/v1", opener)
    assert fx.fetch("CAD", "2026-10-04", "USD") == "0.75"
    assert fx.fetch("USD", "2026-10-04", "USD") == "1"


def test_frankfurter_request_sends_a_user_agent(monkeypatch):
    captured = {}

    class _Body:
        def read(self) -> bytes:
            return b'{"amount":1,"base":"CAD","date":"2026-10-04","rates":{"USD":0.75}}'

        def __enter__(self):
            return self

        def __exit__(self, *_args) -> bool:
            return False

    def fake_urlopen(request, timeout=10):
        captured["request"] = request
        captured["timeout"] = timeout
        return _Body()

    monkeypatch.setattr("kata_service.fx.urlopen", fake_urlopen)
    rate = FrankfurterFx("https://api.frankfurter.dev/v1").fetch("CAD", "2026-10-04", "USD")
    assert rate == "0.75"
    request = captured["request"]
    assert request.full_url == "https://api.frankfurter.dev/v1/2026-10-04?from=CAD&to=USD"
    assert request.get_header("User-agent") == "kata-service/0.1 (+https://github.com/kaanuluer/KATA)"
    assert request.get_header("Accept") == "application/json"
    assert captured["timeout"] == 10


@pytest.fixture
def log_key():
    return private_key_from_seed(b"k" * 32)


@pytest.fixture
def notifier():
    return private_key_from_seed(b"n" * 32)


@pytest.fixture
def principal():
    return private_key_from_seed(b"p" * 32)


@pytest.fixture
def agent():
    return private_key_from_seed(b"a" * 32)
