# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Sandbox check of a UCP checkout. The bureau does not host the session."""

from __future__ import annotations

import hashlib

from kata_intent import Actor, Agreement, private_key_from_seed

from kata_service.bureau import Auth, reset_test_mode, token_hash, use_test_mode

from tests.test_bureau import AT, EXPIRY, _agreement, _auth, _client, _key, _org, _register
from tests.test_mcp import _key as _env_key
from tests.test_mcp import _mcp


def _checkout(amount: object = 1000, **extra) -> dict:
    checkout = {
        "id": "chk_1",
        "currency": "CAD",
        "totals": [{"type": "total", "amount": amount}],
        "signals": {"dev.ucp.buyer_ip": "203.0.113.8", "com.example.risk_score": 1},
        "context": {"note": "provisional", "amount": 999999},
        "ucp": {"version": "2026-08-25"},
        "partnerNote": "kept",
    }
    checkout.update(extra)
    return {"agent_id": "shopper-01", "version": "2026-08-25", "checkout": checkout}


def _ready():
    client = _client(deployment_env="sandbox")
    operator = _org(client, "Harbor Agents", "agent_operator")
    merchant = _org(client, "Techstore", "merchant")
    operator_key = _key(client, operator["org_id"], "ops")
    merchant_key = _key(client, merchant["org_id"], "shop")
    assert operator_key.startswith("gab_test_")
    assert merchant_key.startswith("gab_test_")
    _register(client, operator_key)
    stored = client.post(
        "/v1/agents/shopper-01/intents",
        headers={**_auth(operator_key), "Content-Type": "application/json"},
        content=_agreement().to_json(),
    )
    assert stored.status_code == 200, stored.text
    return client, operator, operator_key, merchant_key


def _plant_live(client, operator: dict) -> None:
    principal = private_key_from_seed(hashlib.sha256(b"ucp-live-principal").digest())
    agent_key = private_key_from_seed(hashlib.sha256(b"ucp-live-agent").digest())
    agreement = Agreement.propose(
        agreement_id="agr_live",
        principal={"display_name": "A Principal", "id": "prn_live", "type": "human"},
        agent={"agent_id": "shopper-01"},
        agent_public_key=agent_key.public,
        intent={
            "allowed_actions": ["purchase"],
            "currency": "CAD",
            "intent_id": "int_live",
            "maximum_amount": 1,
            "purpose": "purchase",
            "time_limit": EXPIRY,
            "version": 1,
        },
        limits={"cumulative_maximum": 1},
        parent_limits={"cumulative_maximum": 1, "currency": "CAD", "maximum_amount": 1},
        actor=Actor("agent", "shopper-01"),
        at=AT,
        expires_at=EXPIRY,
    )
    agreement.accept(principal, AT, confirmed_text=agreement.rendering_preview())
    service = client.app.state.bureau
    live = Auth(
        org_id=operator["org_id"],
        scopes=frozenset(["registry:read", "registry:write", "verify"]),
        kind="key",
        test=False,
    )
    mode = use_test_mode(False)
    try:
        service.register_agent(
            live,
            {
                "agent_id": "shopper-01",
                "principal_id": "prn_live",
                "public_key": agent_key.public.to_jwk(),
                "verification_level": "operator_verified",
            },
        )
        service.store_intent(live, "shopper-01", agreement.to_dict())
        stored = service.repo.get_agent("shopper-01")
        assert stored is not None
        stored["score"] = 111
        service.repo.save_agent(stored)
    finally:
        reset_test_mode(mode)


def test_checkout_uses_the_agreement_and_ignores_signals():
    client, operator, operator_key, merchant_key = _ready()
    _plant_live(client, operator)
    listed = client.get("/v1/agents/shopper-01", headers=_auth(operator_key))
    assert listed.status_code == 200, listed.text
    score = listed.json()["score"]
    assert score != 111
    assert score != 1
    checked = client.post("/v1/sandbox/ucp/verify-checkout", headers=_auth(merchant_key), json=_checkout())
    assert checked.status_code == 200, checked.text
    body = checked.json()
    assert body["verdict"] == "ALLOW"
    assert body["trust_score"]["score"] == score
    assert body["revocations"] == []
    assert body["ucp"]["compatibility_claim"] == "none"
    assert body["ucp"]["hosts_checkout"] is False
    assert body["ucp"]["action"]["amount"] == 10
    assert body["ucp"]["action"]["currency"] == "CAD"
    names = {item["name"]: item for item in body["ucp"]["fields"]}
    assert names["totals.amount"]["status"] == "assumed"
    assert names["currency"]["status"] == "assumed"
    assert names["signals.com.example.risk_score"]["disposition"] == "ignored"
    assert names["context"]["disposition"] == "provisional"
    assert "partnerNote" in body["ucp"]["unmapped"]
    assert "partnerNote" in body["ucp"]["preserved"]
    mode = use_test_mode(False)
    try:
        live = client.app.state.bureau.repo.get_agreement("agr_live")
    finally:
        reset_test_mode(mode)
    assert live is not None
    assert live["document"]["ledger_sequence"] == 0
    mode = use_test_mode(True)
    try:
        test_row = client.app.state.bureau.repo.get_agreement("agr_test")
    finally:
        reset_test_mode(mode)
    assert test_row["document"]["ledger_sequence"] == 1


def test_buyer_asserted_signals_and_bad_amounts_do_not_pass():
    client, _operator, _operator_key, merchant_key = _ready()
    buyer = _checkout()
    buyer["checkout"]["context"]["signals"] = {"dev.ucp.buyer_ip": "203.0.113.9"}
    rejected = client.post("/v1/sandbox/ucp/verify-checkout", headers=_auth(merchant_key), json=buyer)
    assert rejected.status_code == 200, rejected.text
    assert rejected.json()["verdict"] == "DENY"
    assert rejected.json()["reasons"] == ["BUYER_ASSERTED_SIGNAL"]
    mode = use_test_mode(True)
    try:
        row = client.app.state.bureau.repo.get_agreement("agr_test")
    finally:
        reset_test_mode(mode)
    assert row["document"]["ledger_sequence"] == 0

    floated = client.post(
        "/v1/sandbox/ucp/verify-checkout",
        headers=_auth(merchant_key),
        json=_checkout(amount=42.0),
    )
    assert floated.json()["verdict"] == "DENY"
    assert "CHECKOUT_AMOUNT_NOT_MINOR" in floated.json()["reasons"]

    missing = client.post(
        "/v1/sandbox/ucp/verify-checkout",
        headers=_auth(merchant_key),
        json=_checkout(totals=[], currency="USD"),
    )
    assert "CHECKOUT_TOTAL_UNMAPPED" in missing.json()["reasons"]

    bare = _checkout()
    bare["checkout"]["signals"] = {"buyer_ip": "203.0.113.8"}
    malformed = client.post("/v1/sandbox/ucp/verify-checkout", headers=_auth(merchant_key), json=bare)
    assert malformed.status_code == 400
    assert "reverse-domain" in malformed.json()["error"]


def test_revocation_and_mandate_are_bureau_facts():
    client, _operator, operator_key, merchant_key = _ready()
    payload = _checkout()
    payload["checkout"]["ap2"] = {"checkout_mandate": "header.payload.sig"}
    allowed = client.post("/v1/sandbox/ucp/verify-checkout", headers=_auth(merchant_key), json=payload)
    assert allowed.json()["verdict"] == "ALLOW"
    mandate = next(item for item in allowed.json()["ucp"]["fields"] if item["name"] == "ap2.checkout_mandate")
    assert mandate["status"] == "verified"
    assert mandate["disposition"] == "not a grant"
    revoked = client.post("/v1/agents/shopper-01/status", headers=_auth(operator_key), json={"status": "revoked"})
    assert revoked.status_code == 200, revoked.text
    blocked = client.post("/v1/sandbox/ucp/verify-checkout", headers=_auth(merchant_key), json=_checkout(id="chk_2"))
    assert blocked.json()["verdict"] == "DENY"
    assert blocked.json()["reasons"] == ["AGENT_NOT_ACTIVE"]
    assert blocked.json()["revocations"][0]["kind"] == "agent"


def test_route_and_tool_stay_inside_the_sandbox():
    production = _client()
    operator = _org(production, "Harbor Agents", "agent_operator")
    merchant = _org(production, "Techstore", "merchant")
    test_key = _env_key(production, merchant["org_id"], "shop", "test")
    assert test_key.startswith("gab_test_")
    hidden = production.post("/v1/sandbox/ucp/verify-checkout", headers=_auth(test_key), json=_checkout())
    assert hidden.status_code == 404
    assert "/v1/sandbox/ucp/verify-checkout" not in production.get("/openapi.json").text
    unknown = _mcp(
        production,
        "tools/call",
        {"name": "verify_checkout", "arguments": _checkout()},
        token=test_key,
    )
    assert unknown.status_code == 400
    assert unknown.json()["error"]["message"].startswith("Unknown tool")
    listed = _mcp(production, "tools/list", token=test_key)
    assert "verify_checkout" not in [item["name"] for item in listed.json()["result"]["tools"]]

    client, _operator, operator_key, merchant_key = _ready()
    assert client.post("/v1/sandbox/ucp/verify-checkout", json=_checkout()).status_code == 401
    assert client.post(
        "/v1/sandbox/ucp/verify-checkout",
        headers=_auth("admin-test-token"),
        json=_checkout(),
    ).status_code == 403
    client.app.state.bureau.repo.create_key(
        {
            "key_id": "key_live_fixture",
            "org_id": operator["org_id"],
            "name": "live fixture",
            "prefix": "gab_ffffeeee",
            "environment": "live",
            "secret_hash": token_hash("gab_ffffeeee_fixture"),
            "scopes": ["verify"],
            "created_at": "2026-10-16T00:00:00Z",
            "revoked_at": None,
            "rotated_from": None,
        }
    )
    assert (
        client.post(
            "/v1/sandbox/ucp/verify-checkout",
            headers=_auth("gab_ffffeeee_fixture"),
            json=_checkout(),
        ).status_code
        == 403
    )
    assert "/v1/sandbox/ucp/verify-checkout" in client.get("/openapi.json").text
    names = [item["name"] for item in _mcp(client, "tools/list", token=merchant_key).json()["result"]["tools"]]
    assert "verify_checkout" in names
    operator_names = [item["name"] for item in _mcp(client, "tools/list", token=operator_key).json()["result"]["tools"]]
    assert "verify_checkout" in operator_names
    assert "inquire" not in operator_names
    via_tool = _mcp(
        client,
        "tools/call",
        {"name": "verify_checkout", "arguments": _checkout(id="chk_mcp")},
        token=merchant_key,
    )
    assert via_tool.status_code == 200, via_tool.text
    assert via_tool.json()["result"]["structuredContent"]["verdict"] == "ALLOW"
    assert merchant_key not in via_tool.text
    discover = _mcp(client, "server/discover")
    assert "verify_checkout" in discover.json()["result"]["instructions"]
    assert "does not host checkout" in discover.json()["result"]["instructions"]
