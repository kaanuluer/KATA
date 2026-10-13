# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: Apache-2.0
"""The web page and the sample intent check."""

from __future__ import annotations

from fastapi.testclient import TestClient

from kata_service.asgi import create_app
from kata_service.settings import Settings
from kata_service.store import MemoryStore


def _client() -> TestClient:
    settings = Settings(None, None, None, None, None, (), "https://fx.test")
    return TestClient(create_app(settings, MemoryStore()))


def test_home_page_explains_kata_in_english():
    page = _client().get("/")
    assert page.status_code == 200
    assert "text/html" in page.headers["content-type"]
    body = page.text
    assert "Know And Trust Agents" in body
    assert "Who is the agent?" in body
    assert "Who authorized it?" in body
    assert "What was it authorized to do?" in body
    assert "Does this behavior match?" in body
    assert 'id="demo-form"' in body
    assert "Revocation list" in body
    assert "Published keys" in body
    assert "Transparency log" in body
    assert "PolyForm Noncommercial" in body
    assert "open source" not in body.lower()


def test_static_assets_are_served():
    client = _client()
    css = client.get("/assets/app.css")
    script = client.get("/assets/app.js")
    assert css.status_code == 200
    assert "text/css" in css.headers["content-type"]
    assert "--gold" in css.text
    assert script.status_code == 200
    assert "/demo/check" in script.text
    assert client.get("/assets/secret.txt").status_code == 404


def test_demo_allows_denies_and_steps_up():
    client = _client()
    allowed = client.post("/demo/check", json=_payment(1300))
    assert allowed.status_code == 200
    assert allowed.json()["verdict"] == "ALLOW"
    assert "K. Uluer" in allowed.json()["confirmation_text"]
    assert allowed.json()["demo"] is True

    denied = client.post("/demo/check", json=_payment(4200, item="MacBook Pro 14-inch"))
    assert denied.status_code == 200
    assert denied.json()["verdict"] == "DENY"
    assert "AMOUNT_ABOVE_INTENT_CEILING" in denied.json()["reasons"]

    stepped = client.post("/demo/check", json=_payment(1300, include_expiry=False))
    assert stepped.status_code == 200
    assert stepped.json()["verdict"] == "STEP_UP"
    assert "OVER_BROAD_INTENT" in stepped.json()["reasons"]

    rejected = client.post("/demo/check", json={"intent": {"currency": "cadollars"}, "payment": {"amount": 10}})
    assert rejected.status_code == 400


def _payment(amount: int, item: str = "Laptop", include_expiry: bool = True) -> dict:
    return {
        "intent": {
            "maximum_amount": 1500,
            "currency": "CAD",
            "purpose": "purchase",
            "category": "electronics",
            "natural_language": "Find and buy a laptop for me, maximum CAD 1,500.",
            "include_expiry": include_expiry,
            "time_limit": "2026-12-31",
        },
        "payment": {
            "amount": amount,
            "currency": "CAD",
            "merchant": "techstore.example",
            "item": item,
        },
    }
