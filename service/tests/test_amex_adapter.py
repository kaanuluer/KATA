# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Prototype AmEx mapping. Verified status is the published key, not a compatibility claim."""

from __future__ import annotations

import copy

from kata_service.amex_adapter import convert_to_amex, convert_to_kata, load_mapping
from kata_service.bureau import token_hash

from tests.test_bureau import _auth, _client, _org

_SPEC = (
    "https://icm.aexp-static.com/Internet/EnterpriseAPIPortal/products/"
    "nextgen-agentic-payments/nextgen-agentic-payments-openapi-specification.json"
)
_VERIFIED_IDS = {"intent-id", "intent-id-on-intent", "mandate-id"}


def _record() -> dict:
    return {
        "schemaVersion": "1.0.0",
        "intentId": "intent-smoke-01",
        "enrollmentId": "enr-smoke-01",
        "prompt": {
            "promptSummary": "Flight on July 12th",
            "nlpConfidence": 0.92,
        },
        "expirationTs": "2026-12-01T00:00:00Z",
        "spendControl": {
            "maxAmount": "100.00",
            "currency": "USD",
            "expirationTs": "2026-11-15T00:00:00Z",
        },
        "maxAllowedTransactions": "2",
        "purchaseDecision": "DELEGATED",
        "intentStatus": "ACTIVE",
        "proofOfIntent": "signed-jwt",
        "agent": {
            "agentName": "Harbor",
            "llmPlatform": "OPEN_AI",
            "llmVersion": "2026-10-01",
        },
        "user": {"firstName": "Ada", "lastName": "Lovelace"},
        "partnerNote": "keep me",
        "orderContext": {
            "type": "CART",
            "items": [
                {
                    "itemId": "item-1",
                    "name": "Headphones",
                    "unitAmount": "40.00",
                    "currency": "EUR",
                    "quantity": 1,
                    "giftWrap": "yes",
                    "purchaseCriteria": [
                        {
                            "type": "DATE",
                            "fromDate": "2026-11-01T00:00:00Z",
                            "toDate": "2026-11-20T00:00:00Z",
                            "note": "window",
                        }
                    ],
                }
            ],
            "merchants": [
                {
                    "name": "Northwind",
                    "merchantId": 17,
                    "seNumber": "123",
                    "categoryName": "Electronics",
                    "metadata": {"tier": "gold"},
                }
            ],
        },
    }


def test_round_trip_keeps_mapped_values_and_unknown_fields():
    original = _record()
    envelope = convert_to_kata(original)
    assert envelope["schema_version"] == "amex-intent-mapping.v1"
    assert envelope["input_schema_version"] == "1.0.0"
    assert envelope["compatibility_claim"] == "none"
    assert envelope["partial"] is True
    assert envelope["validation"]["schema_version"] == "amex-intent-mapping.v1"
    assert {item["id"] for item in envelope["validation"]["verified"]} == _VERIFIED_IDS
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
    assert limits["currency"] == "USD"
    assert limits["frequency"] == {"max_count": 2, "per": "agreement"}
    assert envelope["agreement"]["mandates"][0]["not_before"] == "2026-11-01T00:00:00Z"
    assert envelope["agreement"]["mandates"][0]["expires_at"] == "2026-12-01T00:00:00Z"
    assert envelope["agreement"]["status"] == "proposed"
    paths = {item["path"] for item in envelope["validation"]["unmapped"]}
    assert "partnerNote" in paths
    assert "prompt.nlpConfidence" in paths
    assert "spendControl.expirationTs" in paths
    assert "orderContext.items.0.currency" in paths
    assert "orderContext.items.0.giftWrap" in paths
    assert "orderContext.items.0.unitAmount" in paths
    assert "orderContext.merchants.0.seNumber" in paths
    assert "orderContext.merchants.0.categoryName" in paths
    assert "orderContext.items.0.purchaseCriteria.0.toDate" in paths
    assert "orderContext.items.0.purchaseCriteria.0.fromDate" not in paths
    assert "orderContext.type" in paths
    assert "enrollmentId" in paths
    assert "purchaseDecision" in paths
    assert "proofOfIntent" in paths
    assert "agent.agentName" in paths
    assert all(item["status"] == "assumed" and item["disposition"] == "preserved" for item in envelope["validation"]["unmapped"])
    assert convert_to_amex(envelope) == original

    edited = copy.deepcopy(envelope)
    edited["agreement"]["mandates"][0]["intent"]["maximum_amount"] = 80
    edited["agreement"]["mandates"][0]["limits"]["frequency"]["max_count"] = 3
    restored = convert_to_amex(edited)
    assert restored["spendControl"]["maxAmount"] == "80"
    assert restored["maxAllowedTransactions"] == "3"
    assert restored["partnerNote"] == "keep me"
    assert restored["orderContext"]["merchants"][0]["seNumber"] == "123"
    assert restored["orderContext"]["items"][0]["giftWrap"] == "yes"
    assert restored["orderContext"]["items"][0]["currency"] == "EUR"


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
        if binding["from"] == "spendControl.maxAmount":
            binding["from"] = "budgetCap"
    moved = convert_to_kata(record, edited)
    assert "spendControl.maxAmount" in {item["path"] for item in moved["validation"]["unmapped"]}
    assert convert_to_amex(moved, edited)["spendControl"]["maxAmount"] == "100.00"
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
    assert missing["agent"]["note"]
    assert "agentName" in missing["agent"]["note"]
    assert "agentId" in missing["agent"]["note"]
    assert "enrollmentId" in missing["principal"]["note"]
    assert "proofOfIntent" in missing["signature"]["note"]
    assert missing["purchase-summary"]["from"] == "prompt.promptSummary"
    assert missing["max-amount"]["from"] == "spendControl.maxAmount"
    assert missing["max-amount"]["required"] is True
    assert missing["intent-expiry"]["from"] == "expirationTs"
    assert missing["intent-expiry"]["required"] is True
    assert missing["transaction-count"]["from"] == "maxAllowedTransactions"
    assert missing["item-currency"]["from"] == "spendControl.currency"
    assert missing["item-currency"]["required"] is True
    assert "agreement_id" not in envelope["agreement"]
    unmapped = {item["path"]: item for item in envelope["validation"]["unmapped"]}
    assert unmapped["partnerNote"]["disposition"] == "preserved"
    assert unmapped["orderContext.items.0.currency"]["status"] == "assumed"
    assert convert_to_amex(envelope) == record
    binding_status = {binding["id"]: binding["status"] for binding in load_mapping()["bindings"]}
    assert {key for key, value in binding_status.items() if value == "verified"} == _VERIFIED_IDS
    for binding in load_mapping()["bindings"]:
        if binding["id"] in _VERIFIED_IDS:
            assert binding["source_field"] == "verified"
            assert binding["citation"] == _SPEC
        else:
            assert binding["status"] == "assumed"


def test_mapping_keys_follow_the_openapi_document():
    mapping = load_mapping()
    sources = {binding["id"]: binding["from"] for binding in mapping["bindings"]}
    assert sources == {
        "intent-id": "intentId",
        "intent-id-on-intent": "intentId",
        "mandate-id": "intentId",
        "purchase-summary": "prompt.promptSummary",
        "max-amount": "spendControl.maxAmount",
        "max-amount-per-transaction": "spendControl.maxAmount",
        "intent-expiry": "expirationTs",
        "intent-expiry-on-mandate": "expirationTs",
        "transaction-count": "maxAllowedTransactions",
        "item-currency": "spendControl.currency",
        "item-currency-on-limits": "spendControl.currency",
        "merchant-names": "orderContext.merchants.*.name",
        "criteria-start": "orderContext.items.0.purchaseCriteria.0.fromDate",
        "criteria-end": "orderContext.items.0.purchaseCriteria.0.toDate",
        "criteria-end-on-intent": "orderContext.items.0.purchaseCriteria.0.toDate",
    }
    count = next(binding for binding in mapping["bindings"] if binding["id"] == "transaction-count")
    assert count["wire"] == "string"
    assert count["transform"] == "integer"
    for binding_id in ("criteria-start", "criteria-end", "criteria-end-on-intent"):
        binding = next(item for item in mapping["bindings"] if item["id"] == binding_id)
        assert binding["when"]["path"].startswith("orderContext.items.0.purchaseCriteria.0.")
        assert binding["when"]["equals"] == "DATE"
    spec = mapping["spec"]
    assert spec["purchase_decision"] == ["NON-DELEGATED", "DELEGATED"]
    assert spec["intent_status_on_create_and_update"] == ["PENDING_STEP_UP", "ACTIVE"]
    assert spec["intent_status_on_notification"] == ["ACTIVE", "CANCEL"]
    assert spec["order_context_type"] == ["INTENT", "CART"]
    assert spec["purchase_criteria_type"] == ["PRICE", "DATE"]
    assert spec["step_up_challenges"] == ["ISSUER_SURFACE", "SECURE_PUSH", "SAFEKEY", "SMS_OTP", "EMAIL_OTP"]
    assert spec["agent_properties"] == ["agentName", "llmPlatform", "llmVersion"]
    assert spec["agent_header"] == "agentId"
    assert spec["llm_platform"] == ["OPEN_AI"]
    assert spec["edit"] == {"method": "PUT", "path": "/payments/digital/v1/agentic-commerce/intents/{intentId}"}
    assert spec["cancel"] == {"method": "DELETE", "path": "/payments/digital/v1/agentic-commerce/intents/{intentId}"}
    assert mapping["source"]["version"] == "1.0.0"
    assert mapping["source"]["openapi"] == "3.1.0"
    assert mapping["source"]["operations"] == 8
    assert mapping["source"]["schemas"] == 64
    assert mapping["input_schema_version"]["field"] == "schemaVersion"
    assert "1.0.0" in mapping["input_schema_version"]["note"]


def test_date_criteria_fill_the_end_only_when_expiration_is_absent():
    record = _record()
    del record["expirationTs"]
    envelope = convert_to_kata(record)
    mandate = envelope["agreement"]["mandates"][0]
    assert mandate["not_before"] == "2026-11-01T00:00:00Z"
    assert mandate["expires_at"] == "2026-11-20T00:00:00Z"
    assert mandate["intent"]["time_limit"] == "2026-11-20T00:00:00Z"
    paths = {item["path"] for item in envelope["validation"]["unmapped"]}
    assert "orderContext.items.0.purchaseCriteria.0.toDate" not in paths
    assert "orderContext.items.0.purchaseCriteria.0.fromDate" not in paths

    priced = _record()
    priced["orderContext"]["items"][0]["purchaseCriteria"][0]["type"] = "PRICE"
    skipped = convert_to_kata(priced)
    assert "not_before" not in skipped["agreement"]["mandates"][0]
    skipped_paths = {item["path"] for item in skipped["validation"]["unmapped"]}
    assert "orderContext.items.0.purchaseCriteria.0.fromDate" in skipped_paths
    assert "orderContext.items.0.purchaseCriteria.0.toDate" in skipped_paths


def test_verified_status_needs_a_citation_and_still_claims_nothing():
    mapping = load_mapping()
    bare = copy.deepcopy(mapping)
    for binding in bare["bindings"]:
        binding.pop("citation", None)
    denied = convert_to_kata(_record(), bare)
    assert denied["validation"]["verified"] == []
    assert any(item["id"] == "intent-id" and item["status"] == "assumed" for item in denied["validation"]["assumed"])

    cited = copy.deepcopy(mapping)
    allowed = convert_to_kata(_record(), cited)
    assert {item["id"] for item in allowed["validation"]["verified"]} == _VERIFIED_IDS
    assert allowed["compatibility_claim"] == "none"

    extra = copy.deepcopy(mapping)
    summary = next(binding for binding in extra["bindings"] if binding["id"] == "purchase-summary")
    summary["status"] = "verified"
    summary.pop("citation", None)
    still_assumed = convert_to_kata(_record(), extra)
    assert "purchase-summary" not in {item["id"] for item in still_assumed["validation"]["verified"]}
    summary["citation"] = _SPEC
    promoted = convert_to_kata(_record(), extra)
    assert "purchase-summary" in {item["id"] for item in promoted["validation"]["verified"]}
    assert promoted["compatibility_claim"] == "none"


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
    assert {item["id"] for item in body["validation"]["verified"]} == _VERIFIED_IDS
    assert "partnerNote" in {item["path"] for item in body["validation"]["unmapped"]}
    assert body["agreement"]["mandates"][0]["intent"]["natural_language_source"] == "Flight on July 12th"
    assert body["agreement"]["mandates"][0]["intent"]["currency"] == "USD"
    restored = sandbox.post("/v1/sandbox/amex-intent/to-amex", headers=_auth(test_token), json=body)
    assert restored.status_code == 200, restored.text
    assert restored.json() == record
    listed = sandbox.get("/openapi.json")
    assert "/v1/sandbox/amex-intent/to-kata" in listed.text
    assert "/v1/sandbox/amex-intent/to-amex" in listed.text
