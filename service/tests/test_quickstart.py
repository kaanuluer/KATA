# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The quickstart page and the small Python client."""

from __future__ import annotations

import hashlib
import io
import json
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from kata_intent.jws import sign_jws
from kata_intent.keys import private_key_from_seed

from kata_service.asgi import create_app
from kata_service.settings import Settings
from kata_service.store import MemoryStore

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "sdk" / "python"))
import gab  # noqa: E402


def _client() -> TestClient:
    settings = Settings(None, None, None, None, None, (), "https://fx.test")
    return TestClient(create_app(settings, MemoryStore()))


def test_quickstart_uses_the_chapters_docs_page():
    client = _client()
    page = client.get("/docs/quickstart")
    assert page.status_code == 200
    body = page.text
    assert 'data-theme="dark"' in body
    assert 'id="theme-toggle"' in body
    assert 'alt="GAB_"' in body
    assert "agent bureau" in body.lower()
    assert "technology company" in body.lower()
    assert "PolyForm Noncommercial" in body
    for needle in (
        "Authorization: Bearer YOUR_KEY",
        "/v1/agents",
        "/v1/verify",
        "/v1/inquiries",
        "/v1/reports",
        "/v1/subscriptions",
        "kata-bureau-alert+jws",
        "/.well-known/kata-keys.json",
        "curl -sS",
        "sdk/python/gab.py",
        "Individuals are not scored",
    ):
        assert needle in body
    for banned in ("open source", "open-source", "credit bureau", "call"):
        assert banned not in body.lower()
    index = client.get("/docs")
    assert 'href="/docs/quickstart"' in index.text


def test_client_sends_the_bearer_token_and_hides_it_on_failure(monkeypatch):
    seen = {}

    def ok(request, timeout):
        seen["url"] = request.full_url
        seen["auth"] = request.get_header("Authorization")
        seen["body"] = request.data
        seen["timeout"] = timeout
        return _Response(b'{"inquiry_id":"inq_1","purpose_code":"payment_authorization"}')

    monkeypatch.setattr(gab, "urlopen", ok)
    client = gab.Client("gab_example_secret", "https://bureau.test", timeout=4)
    result = client.inquire("shopper-01", "payment_authorization")
    assert result["inquiry_id"] == "inq_1"
    assert seen["url"] == "https://bureau.test/v1/inquiries"
    assert seen["auth"] == "Bearer gab_example_secret"
    assert json.loads(seen["body"])["purpose_code"] == "payment_authorization"
    assert seen["timeout"] == 4

    def fail(request, timeout):
        raise gab.HTTPError(
            request.full_url,
            401,
            "no",
            hdrs=None,
            fp=io.BytesIO(b'{"error":"credentials are required gab_example_secret"}'),
        )

    monkeypatch.setattr(gab, "urlopen", fail)
    with pytest.raises(gab.GabError) as caught:
        client.report("shopper-01", "chargeback", "sha256:" + "ab" * 32, "Disputed purchase.")
    assert caught.value.status == 401
    assert "gab_example_secret" not in str(caught.value)
    assert caught.value.message == "request failed"

    def public(request, timeout):
        seen["public_auth"] = request.get_header("Authorization")
        return _Response(b'{"keys":[{"public_key":{"kty":"OKP"}}]}')

    monkeypatch.setattr(gab, "urlopen", public)
    assert client.published_keys() == [{"public_key": {"kty": "OKP"}}]
    assert seen["public_auth"] is None


def test_verify_alert_checks_the_bureau_jws():
    key = private_key_from_seed(hashlib.sha256(b"quickstart-alert").digest())
    document = {
        "alert": {"alert_id": "alt_1", "agent_id": "shopper-01", "kind": "revoked"},
        "at": "2026-10-16T00:00:00Z",
        "kata_bureau_alert": "1",
    }
    message = dict(document)
    message["signature"] = sign_jws(document, key, typ="kata-bureau-alert+jws")
    assert gab.verify_alert(message, key.public.to_jwk()) == document
    tampered = dict(message)
    tampered["alert"] = {"alert_id": "alt_1", "agent_id": "shopper-01", "kind": "test"}
    with pytest.raises(gab.GabError):
        gab.verify_alert(tampered, key.public.to_jwk())
    broken = dict(message)
    broken["signature"] = dict(message["signature"])
    broken["signature"]["signature"] = "aa"
    with pytest.raises(gab.GabError):
        gab.verify_alert(broken, key.public.to_jwk())


class _Response:
    def __init__(self, raw: bytes):
        self.raw = raw

    def read(self) -> bytes:
        return self.raw

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False
