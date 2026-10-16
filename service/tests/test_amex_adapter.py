# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Prototype AmEx mapping. It does not claim a verified field binding."""

from __future__ import annotations

import copy

from kata_service.amex_adapter import convert_to_amex, convert_to_kata, load_mapping
from kata_service.bureau import token_hash

from tests.test_bureau import _auth, _client, _org


def _record() -> dict:
    return {
        "schemaVersion": "sender-draft",
        "intentId": "intent-smoke-01",
        "purchaseSummary": "Flight on July 12th",
        "maxAmount": "100.00",
        "intentExpiry": "2026-12-01T00:00:00Z",
        "maximumNumberOfTransactions": 2,
        "partnerNote": "keep me",
        "orderContext": {
            "type": "Intent",
            "items": [
                {
                    "itemReferenceId": "item-1",
                    "name": "Headphones",
                    "unitAmount": "40.00",
                    "currency": "USD",
                    "quantity": 1,
                    "giftWrap": "yes",
                }
            ],
            "merchants": [
                {
                    "name": "Northwind",
                    "merchantReferenceId": "mer-1",
                    "seNumber": "123",
                    "categoryName": "Electronics",
                    "metadata": {"tier": "gold"},
                }
            ],
            "purchaseCriteria": [
                {
                    "type": "DATE",
                    "fromDate": "2026-11-01T00:00:00Z",
                    "toDate": "2026-11-20T00:00:00Z",
                    "note": "window",
                }
            ],
        },
    }


def test_round_trip_keeps_mapped_values_and_unknown_fields():
    original = _record()
    envelope = convert_to_kata(original)
    assert envelope["schema_version"] == "amex-intent-mapping.v1"
    assert envelope["input_schema_version"] == "sender-draft"
    assert envelope["compatibility_claim"] == "none"
    assert envelope["partial"] is True
    assert envelope["validation"]["schema_version"] == "amex-intent-mapping.v1"
    assert envelope["validation"]["verified"] == []
    intent = envelope["agreement"]["mandates"][0]["intent"]
    limits = envelope["agreement"]["mandates"][0]["limits"]
    assert envelope["agreement"]["agreement_id"] == "intent-smoke-01"
    assert intent["intent_id"] == "intent-smoke-01"
    assert intent["natural_language_source"] == "Flight on July 12th"
    assert intent["maximum_amount"] == 100
    assert intent["currency"] == "USD"
    assert intent["time_limit"] == "2026-12-01T00:00:00Z"
    assert intent["merchant_constraints"] == ["Northwind"]
    assert "Electronics" not in intent["merchant_constraints"]
    assert "purpose" not in intent
    assert limits["per_transaction_maximum"] == 100
    assert limits["frequency"] == {"max_count": 2, "per": "agreement"}
    assert envelope["agreement"]["mandates"][0]["not_before"] == "2026-11-01T00:00:00Z"
    assert envelope["agreement"]["mandates"][0]["expires_at"] == "2026-12-01T00:00:00Z"
    assert envelope["agreement"]["status"] == "proposed"
    paths = {item["path"] for item in envelope["validation"]["unmapped"]}
    assert "partnerNote" in paths
    assert "orderContext.items.0.giftWrap" in paths
    assert "orderContext.items.0.unitAmount" in paths
    assert "orderContext.merchants.0.seNumber" in paths
    assert "orderContext.merchants.0.categoryName" in paths
    assert "orderContext.purchaseCriteria.0.toDate" in paths
    assert all(item["status"] == "assumed" and item["disposition"] == "preserved" for item in envelope["validation"]["unmapped"])
    assert convert_to_amex(envelope) == original

    edited = copy.deepcopy(envelope)
    edited["agreement"]["mandates"][0]["intent"]["maximum_amount"] = 80
    restored = convert_to_amex(edited)
    assert restored["maxAmount"] == "80"
    assert restored["partnerNote"] == "keep me"
    assert restored["orderContext"]["merchants"][0]["seNumber"] == "123"
    assert restored["orderContext"]["items"][0]["giftWrap"] == "yes"


def test_changed_mapping_follows_the_config_file():
    mapping = load_mapping()
    edited = copy.deepcopy(mapping)
    for binding in edited["bindings"]:
        if binding["id"] == "max-amount":
            binding["from"] = "budgetCap"
            binding["to"] = "agreement.mandates.0.intent.constraints.stand_in_ceiling"
    record = _record()
    record["budgetCap"] = "80.00"
    envelope = convert_to_kata(record, edited)
    intent = envelope["agreement"]["mandates"][0]["intent"]
    assert intent["constraints"]["stand_in_ceiling"] == 80
    assert "maximum_amount" not in intent
    assert envelope["agreement"]["mandates"][0]["limits"]["per_transaction_maximum"] == 100
    assert "budgetCap" not in {item["path"] for item in envelope["validation"]["unmapped"]}
    for binding in edited["bindings"]:
        if binding["from"] == "maxAmount":
            binding["from"] = "budgetCap"
    moved = convert_to_kata(record, edited)
    assert "maxAmount" in {item["path"] for item in moved["validation"]["unmapped"]}
    assert convert_to_amex(moved, edited)["maxAmount"] == "100.00"
    assert convert_to_amex(moved, edited)["budgetCap"] == "80.00"


def test_missing_and_unmapped_fields_are_reported():
    record = {"partnerNote": "only", "orderContext": {"items": [{"currency": "usd"}]}}
    envelope = convert_to_kata(record)
    missing = {item["id"]: item for item in envelope["validation"]["missing"]}
    assert missing["intent-id"]["required"] is True
    assert missing["intent-id"]["status"] == "assumed"
    assert missing["input-schema-version"]["from"] == "schemaVersion"
    assert missing["purpose"]["path"] == "agreement.mandates.0.intent.purpose"
    assert missing["principal"]["status"] == "assumed"
    assert "agreement_id" not in envelope["agreement"]
    unmapped = {item["path"]: item for item in envelope["validation"]["unmapped"]}
    assert unmapped["partnerNote"]["disposition"] == "preserved"
    assert unmapped["orderContext.items.0.currency"]["status"] == "assumed"
    assert convert_to_amex(envelope) == record
    for binding in load_mapping()["bindings"]:
        assert binding["status"] == "assumed"


def test_verified_status_needs_a_citation_and_still_claims_nothing():
    mapping = load_mapping()
    bare = copy.deepcopy(mapping)
    bare["bindings"][0]["status"] = "verified"
    bare["bindings"][0].pop("citation", None)
    denied = convert_to_kata(_record(), bare)
    assert denied["validation"]["verified"] == []
    assert any(item["id"] == "intent-id" and item["status"] == "assumed" for item in denied["validation"]["assumed"])

    cited = copy.deepcopy(mapping)
    cited["bindings"][0]["status"] = "verified"
    cited["bindings"][0]["citation"] = "https://americanexpress.io/intent-intelligence-building-trust-in-agentic-commerce/"
    allowed = convert_to_kata(_record(), cited)
    assert any(item["id"] == "intent-id" for item in allowed["validation"]["verified"])
    assert allowed["compatibility_claim"] == "none"


def test_sandbox_route_accepts_only_a_test_key():
    record = _record()
    production = _client()
    operator = _org(production, "Harbor Agents", "agent_operator")
    issued = production.post(
        f"/v1/orgs/{operator['org_id']}/keys",
        headers=_auth("admin-test-token"),
        json={"name": "sandbox", "environment": "test"},
    )
    assert issued.status_code == 200, issued.text
    hidden = production.post(
        "/v1/sandbox/amex-intent/to-kata",
        headers=_auth(issued.json()["token"]),
        json=record,
    )
    assert hidden.status_code == 404
    spec = production.get("/openapi.json")
    assert spec.status_code == 200
    assert "/v1/sandbox/amex-intent/to-kata" not in spec.text

    sandbox = _client(deployment_env="sandbox")
    org = _org(sandbox, "Harbor Agents", "agent_operator")
    test_token = sandbox.post(
        f"/v1/orgs/{org['org_id']}/keys",
        headers=_auth("admin-test-token"),
        json={"name": "sandbox"},
    ).json()["token"]
    assert test_token.startswith("gab_test_")
    assert sandbox.post("/v1/sandbox/amex-intent/to-kata", json=record).status_code == 401
    assert (
        sandbox.post(
            "/v1/sandbox/amex-intent/to-kata",
            headers=_auth("admin-test-token"),
            json=record,
        ).status_code
        == 403
    )
    sandbox.app.state.bureau.repo.create_key(
        {
            "key_id": "key_live_fixture",
            "org_id": org["org_id"],
            "name": "live fixture",
            "prefix": "ffffeeee",
            "environment": "live",
            "secret_hash": token_hash("gab_ffffeeee_fixture"),
            "scopes": ["registry:read"],
            "created_at": "2026-10-16T00:00:00Z",
            "revoked_at": None,
            "rotated_from": None,
        }
    )
    assert (
        sandbox.post(
            "/v1/sandbox/amex-intent/to-kata",
            headers=_auth("gab_ffffeeee_fixture"),
            json=record,
        ).status_code
        == 403
    )
    mapped = sandbox.post("/v1/sandbox/amex-intent/to-kata", headers=_auth(test_token), json=record)
    assert mapped.status_code == 200, mapped.text
    body = mapped.json()
    assert body["schema_version"] == "amex-intent-mapping.v1"
    assert body["compatibility_claim"] == "none"
    assert body["validation"]["verified"] == []
    assert "partnerNote" in {item["path"] for item in body["validation"]["unmapped"]}
    restored = sandbox.post("/v1/sandbox/amex-intent/to-amex", headers=_auth(test_token), json=body)
    assert restored.status_code == 200, restored.text
    assert restored.json() == record
    listed = sandbox.get("/openapi.json")
    assert "/v1/sandbox/amex-intent/to-kata" in listed.text
    assert "/v1/sandbox/amex-intent/to-amex" in listed.text
