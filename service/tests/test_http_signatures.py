# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""RFC 9421 Ed25519 vectors and the Web Bot Auth evidence plugin.

The Ed25519 public key is the RFC 9421 appendix B.1.4 test key. The private
half is not in this file. No directory on the network is contacted.
"""

from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from kata_intent.keys import PublicKey, generate_keypair

from kata_service.asgi import create_app
from kata_service.evidence.http_sig import (
    HttpMessage,
    HttpSignatureError,
    directory_url,
    query_param,
    signature_material,
    verify_ed25519,
)
from kata_service.evidence.jwks import FetchFailed
from kata_service.evidence.store import MemoryEvidenceStore
from kata_service.evidence.verifier import verifier_for
from kata_service.evidence.web_bot_auth import DIRECTORY_MEDIA_TYPE, ed25519_thumbprint, publishable_jwk
from kata_service.settings import Settings, settings_from_env
from kata_service.store import MemoryStore

RFC_X = "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"
RFC_THUMBPRINT = "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U"
NOW = datetime(2026, 11, 24, 12, 0, tzinfo=timezone.utc)
PUBLIC = lambda host: ["8.8.8.8"]  # noqa: E731 — test resolver, never dialed


def _rfc_key() -> PublicKey:
    pad = "=" * (-len(RFC_X) % 4)
    return PublicKey(base64.urlsafe_b64decode(RFC_X + pad), "EdDSA")


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


class ScriptedFetch:
    def __init__(self, bodies: list[bytes] | None = None) -> None:
        self.bodies = list(bodies or [])
        self.calls = 0
        self.urls: list[str] = []

    def __call__(self, url: str, timeout: float) -> bytes:
        del timeout
        self.calls += 1
        self.urls.append(url)
        if not self.bodies:
            raise FetchFailed("jwks fetch failed")
        return self.bodies.pop(0)


def _jwk(private, kid: str) -> dict:
    document = private.public.to_jwk()
    document["kid"] = kid
    document["alg"] = "EdDSA"
    document["use"] = "sig"
    return document


def _jwks(*keys: dict) -> bytes:
    return json.dumps({"keys": list(keys)}).encode("utf-8")


def test_rfc_9421_b26_ed25519_request():
    message = HttpMessage(
        method="POST",
        path="/foo",
        authority="example.com",
        query="param=Value&Pet=dog",
        headers=[
            ("host", "example.com"),
            ("date", "Tue, 20 Apr 2021 02:07:55 GMT"),
            ("content-type", "application/json"),
            ("content-length", "18"),
            (
                "signature-input",
                'sig-b26=("date" "@method" "@path" "@authority" "content-type" "content-length")'
                ';created=1618884473;keyid="test-key-ed25519"',
            ),
            (
                "signature",
                "sig-b26=:wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==:",
            ),
        ],
    )
    base, _raw, _covered, label = signature_material(message)
    assert label == "sig-b26"
    assert base == (
        '"date": Tue, 20 Apr 2021 02:07:55 GMT\n'
        '"@method": POST\n'
        '"@path": /foo\n'
        '"@authority": example.com\n'
        '"content-type": application/json\n'
        '"content-length": 18\n'
        '"@signature-params": ("date" "@method" "@path" "@authority" "content-type" "content-length")'
        ';created=1618884473;keyid="test-key-ed25519"'
    )
    assert verify_ed25519(message, _rfc_key()) is True


def test_rfc_9421_b4_ed25519_field_transformations():
    signature_input = (
        'transform=("@method" "@path" "@authority" "accept");created=1618884473;keyid="test-key-ed25519"'
    )
    signature = (
        "transform=:ZT1kooQsEHpZ0I1IjCqtQppOmIqlJPeo7DHR3SoMn0s5JZ1eRGS0A+vyYP9t/LXlh5QMFFQ6cpLt2m0pmj3NDA==:"
    )

    def message(method: str, authority: str, accept: list[str], extra: list[tuple[str, str]] | None = None) -> HttpMessage:
        headers = [("host", authority), ("signature-input", signature_input), ("signature", signature)]
        headers.extend(extra or [])
        headers.extend(("accept", value) for value in accept)
        return HttpMessage(method=method, path="/demo", authority=authority, headers=headers)

    original = message("GET", "example.org", ["application/json", "*/*"], [("date", "Fri, 15 Jul 2022 14:24:55 GMT")])
    assert verify_ed25519(original, _rfc_key()) is True
    added = message(
        "GET",
        "example.org",
        ["application/json", "*/*"],
        [("date", "Fri, 15 Jul 2022 14:24:55 GMT"), ("accept-language", "en-US,en;q=0.5")],
    )
    added.query = "name1=Value1&Name2=value2&param=added"
    assert verify_ed25519(added, _rfc_key()) is True
    collapsed = message("GET", "example.org", ["application/json, */*"], [("referer", "https://developer.example.org/demo")])
    assert verify_ed25519(collapsed, _rfc_key()) is True
    reordered = HttpMessage(
        method="GET",
        path="/demo",
        authority="example.org",
        headers=[
            ("accept", "application/json"),
            ("accept", "*/*"),
            ("date", "Fri, 15 Jul 2022 14:24:55 GMT"),
            ("host", "example.org"),
            ("signature-input", signature_input),
            ("signature", signature),
        ],
    )
    assert verify_ed25519(reordered, _rfc_key()) is True
    changed = message("POST", "example.com", ["application/json", "*/*"])
    assert verify_ed25519(changed, _rfc_key()) is False
    swapped = message("GET", "example.org", ["*/*", "application/json"])
    assert verify_ed25519(swapped, _rfc_key()) is False


def test_web_bot_auth_ed25519_vectors_e2():
    common = (
        ';created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519"'
    )
    dictionary = HttpMessage(
        authority="example.com",
        headers=[
            ("signature-agent", 'sig2="https://signature-agent.test"'),
            (
                "signature-input",
                'sig2=("@authority" "signature-agent";key="sig2")'
                + common
                + ';expires=4889289600;nonce="n9p433xm+NJ3ph3upfBIGmsuwHw387YV7Q/F+6BSpGCVjYCqQw6rznNA8PVVLySrAWsv0hQtFioQb6E1YsauiA=="'
                + ';tag="web-bot-auth"',
            ),
            (
                "signature",
                "sig2=:CGokAoY/FrPpyuzTe1Fb2kLTAH9Idw6qSFd1+D77r1firsMRCxeuLu5e6O+ek3zQgDMAzjiXtLVfqE00xnABCQ==:",
            ),
        ],
    )
    legacy = HttpMessage(
        authority="example.com",
        headers=[
            ("signature-agent", '"https://signature-agent.test"'),
            (
                "signature-input",
                'sig2=("@authority" "signature-agent")'
                + common
                + ';expires=1735693200;nonce="e8N7S2MFd/qrd6T2R3tdfAuuANngKI7LFtKYI/vowzk4lAZYadIX6wW25MwG7DCT9RUKAJ0qVkU0mEeLElW1qg=="'
                + ';tag="web-bot-auth"',
            ),
            (
                "signature",
                "sig2=:jdq0SqOwHdyHr9+r5jw3iYZH6aNGKijYp/EstF4RQTQdi5N5YYKrD+mCT1HA1nZDsi6nJKuHxUi/5Syp3rLWBA==:",
            ),
        ],
    )
    assert verify_ed25519(dictionary, _rfc_key(), label="sig2") is True
    assert verify_ed25519(legacy, _rfc_key(), label="sig2") is True
    base, _raw, _covered, _label = signature_material(dictionary, label="sig2")
    assert '"signature-agent";key="sig2": "https://signature-agent.test"\n' in base


def test_query_param_component_matches_the_rfc_examples():
    assert query_param("param=value&foo=bar&baz=batman&qux=", "baz") == "batman"
    assert query_param("param=value&foo=bar&baz=batman&qux=", "qux") == ""
    assert query_param("param=value&foo=bar&baz=batman&qux=", "param") == "value"
    encoded = "var=this%20is%20a%20big%0Amultiline%20value&bar=with+plus+whitespace"
    assert query_param(encoded, "var") == "this%20is%20a%20big%0Amultiline%20value"
    assert query_param(encoded, "bar") == "with%20plus%20whitespace"
    with pytest.raises(HttpSignatureError):
        query_param("a=1&a=2", "a")


def test_ed25519_thumbprint_matches_the_directory_example():
    assert ed25519_thumbprint(RFC_X) == RFC_THUMBPRINT


def test_origin_directory_uses_the_well_known_path_and_a_path_is_kept():
    assert directory_url("https://signature-agent.test") == (
        "https://signature-agent.test/.well-known/http-message-signatures-directory"
    )
    assert directory_url("https://signature-agent.test/jwks.json") == "https://signature-agent.test/jwks.json"
    with pytest.raises(HttpSignatureError) as caught:
        directory_url("http://signature-agent.test/.well-known/http-message-signatures-directory")
    assert caught.value.reason == "directory_url_rejected"


def _plugin_message(private, *, created: int, expires: int, nonce: str = "nonce-1", kid: str = "kid-1", signature: bytes | None = None, headers: list[tuple[str, str]] | None = None, agent: str = 'sig="https://bot.example"', cover_date: bool = False) -> HttpMessage:
    covered = '"@authority" "signature-agent";key="sig"'
    if cover_date:
        covered = '"date" ' + covered
    signature_input = (
        f"sig=({covered});created={created};expires={expires};keyid=\"{kid}\";alg=\"ed25519\";nonce=\"{nonce}\";tag=\"web-bot-auth\""
    )
    rows = [("signature-agent", agent), ("signature-input", signature_input)]
    if headers:
        rows.extend(headers)
    placeholder = signature if signature is not None else b"\x00" * 64
    rows.append(("signature", "sig=:" + _b64(placeholder) + ":"))
    message = HttpMessage(method="GET", path="/path", authority="origin.example", headers=rows)
    if signature is None:
        base, _raw, _covered, _label = signature_material(message, label="sig")
        signed = private.sign(base.encode("ascii"))
        message.headers = [item for item in message.headers if item[0] != "signature"]
        message.headers.append(("signature", "sig=:" + _b64(signed) + ":"))
    return message


def _material(message: HttpMessage) -> dict:
    return {
        "source": "web-bot-auth",
        "method": message.method,
        "path": message.path,
        "authority": message.authority,
        "query": message.query,
        "scheme": message.scheme,
        "headers": [[name, value] for name, value in message.headers],
    }


def _verify(store, message: HttpMessage, private, *, fetch: ScriptedFetch | None = None, resolve=PUBLIC, now: datetime = NOW, kid: str = "kid-1"):
    if fetch is None:
        fetch = ScriptedFetch([_jwks(_jwk(private, kid))])
    verifier = verifier_for("web-bot-auth", store, fetch=fetch, resolve=resolve)
    return verifier.verify(_material(message), now=now), fetch


def test_plugin_accepts_a_fresh_ed25519_signature_and_rejects_a_replay():
    private = generate_keypair("EdDSA")
    created = int(NOW.timestamp())
    message = _plugin_message(private, created=created, expires=created + 30)
    store = MemoryEvidenceStore()
    evidence, fetch = _verify(store, message, private)
    assert evidence["result"] == "valid"
    assert evidence["reason"] == "ok"
    assert evidence["source"] == "web-bot-auth"
    assert evidence["issuer"] == "https://bot.example/.well-known/http-message-signatures-directory"
    assert evidence["key_id"] == "kid-1"
    assert fetch.urls == ["https://bot.example/.well-known/http-message-signatures-directory"]
    again, fetch = _verify(store, message, private, fetch=fetch)
    assert again["result"] == "invalid"
    assert again["reason"] == "replay"
    assert fetch.calls == 1


def test_wrong_signature_does_not_consume_the_nonce():
    private = generate_keypair("EdDSA")
    created = int(NOW.timestamp())
    bad = _plugin_message(private, created=created, expires=created + 30, signature=b"\x11" * 64)
    store = MemoryEvidenceStore()
    evidence, fetch = _verify(store, bad, private)
    assert evidence["result"] == "invalid"
    assert evidence["reason"] == "signature"
    good = _plugin_message(private, created=created, expires=created + 30)
    again, _fetch = _verify(store, good, private, fetch=fetch)
    assert again["result"] == "valid"


def test_unknown_key_expired_window_and_missing_component(store_memory):
    private = generate_keypair("EdDSA")
    created = int(NOW.timestamp())
    message = _plugin_message(private, created=created, expires=created + 30, kid="kid-1")
    fetch = ScriptedFetch([_jwks(_jwk(private, "kid-other"))])
    unknown, fetch = _verify(store_memory, message, private, fetch=fetch)
    assert unknown["reason"] == "unknown_key"
    assert unknown["result"] == "invalid"

    expired_message = _plugin_message(private, created=created - 120, expires=created - 61)
    expired, fetch = _verify(MemoryEvidenceStore(), expired_message, private)
    assert expired["reason"] == "expired"
    assert fetch.calls == 0

    future = _plugin_message(private, created=created, expires=created + 61)
    window, fetch = _verify(MemoryEvidenceStore(), future, private)
    assert window["reason"] == "window"
    assert fetch.calls == 0

    missing = _plugin_message(
        private,
        created=created,
        expires=created + 30,
        cover_date=True,
        signature=b"\x22" * 64,
    )
    missed, fetch = _verify(MemoryEvidenceStore(), missing, private)
    assert missed["reason"] == "missing_component"
    assert fetch.calls == 0


@pytest.fixture
def store_memory():
    return MemoryEvidenceStore()


def test_ssrf_targets_and_redirects_are_not_followed(monkeypatch):
    private = generate_keypair("EdDSA")
    created = int(NOW.timestamp())
    blocked = [
        'sig="https://127.0.0.1/jwks.json"',
        'sig="https://10.0.0.8/.well-known/http-message-signatures-directory"',
        'sig="https://192.168.1.1/"',
        'sig="https://169.254.169.254/.well-known/http-message-signatures-directory"',
        'sig="https://[::1]/.well-known/http-message-signatures-directory"',
        'sig="https://localhost/.well-known/http-message-signatures-directory"',
        'sig="https://metadata.google.internal/.well-known/http-message-signatures-directory"',
        'sig="http://8.8.8.8/.well-known/http-message-signatures-directory"',
    ]
    for agent in blocked:
        fetch = ScriptedFetch([_jwks(_jwk(private, "kid-1"))])
        message = _plugin_message(private, created=created, expires=created + 30, agent=agent)
        evidence, fetch = _verify(MemoryEvidenceStore(), message, private, fetch=fetch)
        assert evidence["result"] == "unverifiable", agent
        assert evidence["reason"] == "directory_url_rejected", agent
        assert fetch.calls == 0, agent
        assert "127.0.0.1" not in json.dumps(evidence)
        assert "169.254.169.254" not in json.dumps(evidence)
        assert "metadata.google.internal" not in json.dumps(evidence)

    fetch = ScriptedFetch([_jwks(_jwk(private, "kid-1"))])
    message = _plugin_message(private, created=created, expires=created + 30, agent='sig="https://rebind.example/jwks.json"')
    rebound, _fetch = _verify(
        MemoryEvidenceStore(),
        message,
        private,
        fetch=fetch,
        resolve=lambda host: ["10.0.0.4"],
    )
    assert rebound["reason"] == "directory_url_rejected"
    assert fetch.calls == 0

    dialed: list[tuple] = []

    class FakeSocket:
        def __init__(self) -> None:
            self.buf = (
                b"HTTP/1.1 302 Found\r\nLocation: https://169.254.169.254/latest/meta-data/\r\nContent-Length: 0\r\n\r\n"
            )

        def sendall(self, data: bytes) -> None:
            del data

        def recv(self, size: int) -> bytes:
            chunk = self.buf[:size]
            self.buf = self.buf[size:]
            return chunk

        def settimeout(self, timeout: float) -> None:
            del timeout

        def close(self) -> None:
            return None

    def connect(address, timeout):
        del timeout
        dialed.append(address)
        return FakeSocket()

    class Context:
        def wrap_socket(self, raw, server_hostname=None):
            del server_hostname
            return raw

    monkeypatch.setattr("kata_service.evidence.jwks.socket.create_connection", connect)
    monkeypatch.setattr("kata_service.evidence.jwks.ssl.create_default_context", lambda: Context())
    message = _plugin_message(private, created=created, expires=created + 30, agent='sig="https://bot.example"')
    verifier = verifier_for("web-bot-auth", MemoryEvidenceStore(), resolve=PUBLIC)
    evidence = verifier.verify(_material(message), now=NOW)
    assert evidence["reason"] == "jwks_fetch_failed"
    assert dialed == [("8.8.8.8", 443)]
    assert "169.254.169.254" not in json.dumps(evidence)


def test_directory_flag_off_is_the_same_404_as_an_unknown_path():
    client = TestClient(_app())
    unknown = client.get("/.well-known/not-a-real-directory")
    directory = client.get("/.well-known/http-message-signatures-directory")
    assert directory.status_code == 404
    assert directory.status_code == unknown.status_code
    assert directory.content == unknown.content
    assert directory.headers["content-type"] == unknown.headers["content-type"]
    assert "/.well-known/http-message-signatures-directory" not in client.get("/openapi.json").text
    assert settings_from_env({}).http_message_signatures is False
    assert settings_from_env({"GAB_HTTP_MESSAGE_SIGNATURES": "1"}).http_message_signatures is True


def test_directory_publishes_only_a_public_jwk():
    private = generate_keypair("EdDSA")
    public = private.public.to_jwk()
    public.pop("kid", None)
    client = TestClient(_app(http_message_signatures=True, http_message_signatures_jwk=public))
    response = client.get("/.well-known/http-message-signatures-directory")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith(DIRECTORY_MEDIA_TYPE)
    body = response.json()
    assert body["keys"][0]["x"] == public["x"]
    assert body["keys"][0]["kid"] == ed25519_thumbprint(public["x"])
    assert "d" not in body["keys"][0]
    unset = TestClient(_app(http_message_signatures=True))
    assert unset.get("/.well-known/http-message-signatures-directory").status_code == 404
    named = dict(public)
    named["kid"] = "published-kid"
    kept = TestClient(_app(http_message_signatures=True, http_message_signatures_jwk=named))
    assert kept.get("/.well-known/http-message-signatures-directory").json()["keys"][0]["kid"] == "published-kid"
    secret = dict(public)
    secret["d"] = base64.urlsafe_b64encode(private.seed).decode("ascii").rstrip("=")
    hidden = TestClient(_app(http_message_signatures=True, http_message_signatures_jwk=secret))
    refused = hidden.get("/.well-known/http-message-signatures-directory")
    assert refused.status_code == 404
    assert secret["d"] not in refused.text
    assert publishable_jwk(secret) is None
    listed = client.get("/openapi.json")
    assert "/.well-known/http-message-signatures-directory" in listed.text


def test_long_lived_draft_vector_is_outside_the_window():
    private = generate_keypair("EdDSA")
    created = 1735689600
    moment = datetime.fromtimestamp(created, timezone.utc)
    message = _plugin_message(private, created=created, expires=created + 86400)
    evidence, fetch = _verify(MemoryEvidenceStore(), message, private, now=moment)
    assert evidence["reason"] == "window"
    assert fetch.calls == 0
    later = moment + timedelta(seconds=61)
    stale, _fetch = _verify(
        MemoryEvidenceStore(),
        _plugin_message(private, created=created, expires=created + 30),
        private,
        now=later,
    )
    assert stale["reason"] == "expired"


def _app(**overrides) -> object:
    settings = Settings(
        database_url=None,
        schema_url=None,
        log_signing_seed=None,
        push_notifier_jwk=None,
        append_token=None,
        published_keys=(),
        fx_source_url="https://fx.test",
        **overrides,
    )
    return create_app(settings, MemoryStore())
