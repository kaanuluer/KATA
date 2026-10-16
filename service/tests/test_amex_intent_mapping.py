# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The AmEx mapping note is a document. It does not add an adapter."""

from fastapi.testclient import TestClient

from kata_service.asgi import create_app
from kata_service.settings import Settings
from kata_service.store import MemoryStore


def test_amex_intent_mapping_page_cites_the_framework_and_stays_a_note():
    client = TestClient(
        create_app(Settings(None, None, None, None, None, (), "https://fx.test"), MemoryStore())
    )
    page = client.get("/docs/amex-intent-mapping")
    assert page.status_code == 200
    text = page.text
    assert (
        "https://americanexpress.io/intent-intelligence-building-trust-in-agentic-commerce/"
        in text
    )
    assert "13 October 2026" in text
    assert "Nothing here is implemented" in text
    assert "agent bureau" in text.lower()
    assert "PolyForm Noncommercial" in text
    assert "Verified" in text
    assert "Assumed" in text
    assert "Not accessible" in text
    folded = text.lower()
    assert "call" not in folded
    assert "open source" not in folded
    assert "open-source" not in folded
    assert "credit bureau" not in folded
