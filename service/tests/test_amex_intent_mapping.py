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
    assert (
        "https://icm.aexp-static.com/Internet/EnterpriseAPIPortal/products/"
        "nextgen-agentic-payments/nextgen-agentic-payments-openapi-specification.json"
        in text
    )
    assert "OpenAPI 3.1.0" in text
    assert "April 28, 2026" in text
    assert "1.0.0" in text
    assert "prompt.promptSummary" in text
    assert "prompt.nlpConfidence" in text
    assert "spendControl.maxAmount" in text
    assert "spendControl.currency" in text
    assert "expirationTs" in text
    assert "maxAllowedTransactions" in text
    assert "orderContext.items" in text
    assert "purchaseCriteria" in text
    assert "PUT" in text
    assert "DELETE" in text
    assert "DELEGATED" in text
    assert "NON-DELEGATED" in text
    assert "PENDING_STEP_UP" in text
    assert "ACTIVE" in text
    assert "CANCEL" in text
    assert "proofOfIntent" in text
    assert "agentName" in text
    assert "agentId" in text
    assert "enrollmentId" in text
    assert "INTENT" in text
    assert "CART" in text
    assert "8" in text
    assert "64" in text
    folded = text.lower()
    assert "call" not in folded
    assert "open source" not in folded
    assert "open-source" not in folded
    assert "credit bureau" not in folded
