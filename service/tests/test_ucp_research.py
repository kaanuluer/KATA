# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The UCP note is a document. It does not add a protocol route."""

from fastapi.testclient import TestClient

from kata_service.asgi import create_app
from kata_service.settings import Settings
from kata_service.store import MemoryStore


def test_ucp_research_page_cites_the_spec_and_stays_a_note():
    client = TestClient(
        create_app(Settings(None, None, None, None, None, (), "https://fx.test"), MemoryStore())
    )
    page = client.get("/docs/ucp-research")
    assert page.status_code == 200
    text = page.text
    assert "v2026-08-25" in text
    assert "https://ucp.dev/2026-08-25/specification/overview/" in text
    assert "https://ucp.dev/2026-08-25/specification/shopping/checkout/mcp/" in text
    assert "https://ucp.dev/2026-08-25/specification/payment/extensions/ap2-mandates/" in text
    assert "agent bureau" in text.lower()
    assert "PolyForm Noncommercial" in text
    assert "sandbox consumer" in text.lower()
    assert "does not host checkout" in text.lower()
    assert "/v1/sandbox/ucp/verify-checkout" in text
    assert "Nothing here is implemented" not in text
    hidden = client.post("/v1/sandbox/ucp/verify-checkout", json={})
    assert hidden.status_code == 404
    assert "## Verified" in text or "Verified" in text
    assert "Assumed" in text
    folded = text.lower().replace("tools/call", "")
    assert "call" not in folded
    assert "open source" not in folded
    assert "open-source" not in folded
    assert "credit bureau" not in folded
    missing = client.get("/.well-known/ucp")
    assert missing.status_code == 404
