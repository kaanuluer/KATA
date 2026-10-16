# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""MCP streamable HTTP tests. Memory repository only. No network and no real keys."""

from __future__ import annotations

import hashlib

from fastapi.testclient import TestClient

from kata_intent import Actor, Agreement, private_key_from_seed

from kata_service.asgi import create_app
from kata_service.bureau import token_hash
from kata_service.mcp_http import PROTOCOL_VERSION
from kata_service.settings import Settings
from kata_service.store import MemoryStore

AT = "2026-10-04T13:55:00Z"
EXPIRY = "2026-12-31T23:59:59Z"
ADMIN = "admin-test-token"


def _settings(**overrides) -> Settings:
    base = dict(
        database_url=None,
        schema_url=None,
        log_signing_seed=hashlib.sha256(b"bureau-test-log").digest(),
        push_notifier_jwk=None,
        append_token=None,
        published_keys=(),
        fx_source_url="https://fx.test",
        admin_token=ADMIN,
        rate_limit_per_minute=30,
        report_daily_cap=5,
    )
    base.update(overrides)
    return Settings(**base)


def _client(**overrides) -> TestClient:
    return TestClient(create_app(_settings(**overrides), MemoryStore()))


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _org(client: TestClient, name: str, org_type: str) -> dict:
    response = client.post("/v1/orgs", headers=_auth(ADMIN), json={"name": name, "org_type": org_type})
    assert response.status_code == 200, response.text
    return response.json()


def _key(client: TestClient, org_id: str, name: str, environment: str | None = None) -> str:
    body: dict[str, str] = {"name": name}
    if environment:
        body["environment"] = environment
    response = client.post(f"/v1/orgs/{org_id}/keys", headers=_auth(ADMIN), json=body)
    assert response.status_code == 200, response.text
    return response.json()["token"]


def _meta() -> dict:
    return {
        "io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION,
        "io.modelcontextprotocol/clientInfo": {"name": "gab-test", "version": "1"},
        "io.modelcontextprotocol/clientCapabilities": {},
    }


def _mcp(client: TestClient, method: str, params: dict | None = None, token: str | None = None, headers: dict | None = None, ident: int = 1):
    body_params = dict(params or {})
    body_params["_meta"] = _meta()
    sent = {
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
        "MCP-Protocol-Version": PROTOCOL_VERSION,
        "Mcp-Method": method,
    }
    if method == "tools/call":
        sent["Mcp-Name"] = str(body_params.get("name") or "")
    if token:
        sent["Authorization"] = f"Bearer {token}"
    if headers:
        sent.update(headers)
    return client.post(
        "/mcp",
        headers=sent,
        json={"jsonrpc": "2.0", "id": ident, "method": method, "params": body_params},
    )


def test_discover_and_headers_follow_the_2026_07_28_revision():
    client = _client()
    found = _mcp(client, "server/discover")
    assert found.status_code == 200, found.text
    body = found.json()["result"]
    assert body["supportedVersions"] == ["2026-07-28"]
    assert body["capabilities"]["tools"] == {}
    assert "gab_test_" in body["instructions"]
    assert found.json()["id"] == 1

    mismatch = _mcp(client, "server/discover", headers={"MCP-Protocol-Version": "2025-11-25"})
    assert mismatch.status_code == 400
    assert mismatch.json()["error"]["code"] == -32020

    unsupported = client.post(
        "/mcp",
        headers={
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": "2025-11-25",
            "Mcp-Method": "server/discover",
        },
        json={
            "jsonrpc": "2.0",
            "id": 2,
            "method": "server/discover",
            "params": {"_meta": {"io.modelcontextprotocol/protocolVersion": "2025-11-25"}},
        },
    )
    assert unsupported.status_code == 400
    assert unsupported.json()["error"]["code"] == -32022
    assert unsupported.json()["error"]["data"]["supported"] == ["2026-07-28"]

    missing = client.post("/mcp", json={"jsonrpc": "2.0", "method": "notifications/initialized"})
    assert missing.status_code == 202
    assert missing.content == b""

    assert client.get("/mcp").status_code == 405
    assert client.delete("/mcp").status_code == 405
    foreign = _mcp(client, "server/discover", headers={"Origin": "https://evil.example"})
    assert foreign.status_code == 403
    assert "id" not in foreign.json()


def test_tools_require_an_api_key_and_hide_it():
    client = _client()
    operator = _org(client, "Harbor Agents", "agent_operator")
    merchant = _org(client, "Techstore", "merchant")
    operator_key = _key(client, operator["org_id"], "ops")
    merchant_key = _key(client, merchant["org_id"], "shop")
    absent = _mcp(client, "tools/list")
    assert absent.status_code == 401
    assert absent.headers["www-authenticate"] == "Bearer"
    planted = "gab_test_deadbeef_planted-token"
    denied = _mcp(client, "tools/list", token=planted)
    assert denied.status_code == 401
    assert planted not in denied.text

    listed = _mcp(client, "tools/list", token=merchant_key)
    assert listed.status_code == 200, listed.text
    names = [item["name"] for item in listed.json()["result"]["tools"]]
    assert names == ["verify_agent", "inquire", "report", "check_revocation", "fetch_signed_receipt"]
    inquire = next(item for item in listed.json()["result"]["tools"] if item["name"] == "inquire")
    assert "purpose_code" in inquire["inputSchema"]["properties"]
    assert "gab_test_" in inquire["description"]

    operator_tools = [item["name"] for item in _mcp(client, "tools/list", token=operator_key).json()["result"]["tools"]]
    assert "inquire" not in operator_tools
    assert "verify_agent" in operator_tools

    unknown = _mcp(client, "tools/call", {"name": "missing_tool", "arguments": {}}, token=merchant_key)
    assert unknown.status_code == 400
    assert unknown.json()["error"]["code"] == -32602
    assert merchant_key not in unknown.text

    bad = _mcp(
        client,
        "tools/call",
        {"name": "inquire", "arguments": {"agent_id": "shopper-01", "purpose_code": "nope"}},
        token=merchant_key,
    )
    assert bad.status_code == 200
    assert bad.json()["result"]["isError"] is True
    assert merchant_key not in bad.text

    session = "gab_sess_fixture"
    client.app.state.bureau.repo.put_session(
        {
            "token_hash": token_hash(session),
            "kind": "portal",
            "subject_id": "prn_fixture",
            "expires_at": "2099-01-01T00:00:00Z",
        }
    )
    refused = _mcp(client, "tools/list", token=session)
    assert refused.status_code == 401
    assert session not in refused.text


def test_test_key_uses_sandbox_isolation_and_rate_limits():
    client = _client()
    operator = _org(client, "Harbor Agents", "agent_operator")
    merchant = _org(client, "Techstore", "merchant")
    live_operator = _key(client, operator["org_id"], "live")
    test_operator = _key(client, operator["org_id"], "test-ops", "test")
    live_merchant = _key(client, merchant["org_id"], "live-shop")
    test_merchant = _key(client, merchant["org_id"], "test-shop", "test")
    assert test_merchant.startswith("gab_test_")

    agent = private_key_from_seed(hashlib.sha256(b"bureau-agent").digest())
    principal = private_key_from_seed(hashlib.sha256(b"bureau-principal").digest())
    registered = client.post(
        "/v1/agents",
        headers=_auth(live_operator),
        json={
            "agent_id": "shopper-01",
            "principal_id": "prn_person",
            "public_key": agent.public.to_jwk(),
            "verification_level": "operator_verified",
        },
    )
    assert registered.status_code == 200, registered.text
    agreement = Agreement.propose(
        agreement_id="agr_test",
        principal={"display_name": "A Principal", "id": "prn_person", "type": "human"},
        agent={"agent_id": "shopper-01"},
        agent_public_key=agent.public,
        intent={
            "allowed_actions": ["purchase"],
            "currency": "CAD",
            "intent_id": "int_laptop",
            "maximum_amount": 1500,
            "purpose": "purchase",
            "time_limit": EXPIRY,
            "version": 1,
        },
        limits={"cumulative_maximum": 2000},
        parent_limits={"cumulative_maximum": 2000, "currency": "CAD", "maximum_amount": 1500},
        actor=Actor("agent", "shopper-01"),
        at=AT,
        expires_at=EXPIRY,
    )
    agreement.accept(principal, AT, confirmed_text=agreement.rendering_preview())
    stored = client.post(
        "/v1/agents/shopper-01/intents",
        headers={**_auth(live_operator), "Content-Type": "application/json"},
        content=agreement.to_json(),
    )
    assert stored.status_code == 200, stored.text

    checked = _mcp(
        client,
        "tools/call",
        {
            "name": "verify_agent",
            "arguments": {
                "agent_id": "shopper-01",
                "action": {
                    "action_id": "act_live",
                    "action_type": "purchase",
                    "amount": 10,
                    "context": {"merchant": "techstore.example"},
                    "currency": "CAD",
                    "item": "Laptop",
                    "parameters": {"merchant": "techstore.example", "quantity": 1},
                    "proposed_at": AT,
                },
            },
        },
        token=live_merchant,
    )
    assert checked.status_code == 200, checked.text
    assert checked.json()["result"]["isError"] is False
    assert checked.json()["result"]["structuredContent"]["verdict"] == "ALLOW"
    assert live_merchant not in checked.text

    filed = _mcp(
        client,
        "tools/call",
        {
            "name": "report",
            "arguments": {
                "agent_id": "shopper-01",
                "kind": "fraud_incident",
                "evidence_hash": "sha256:" + "ab" * 32,
                "summary": "Disputed charge",
            },
        },
        token=live_merchant,
    )
    assert filed.status_code == 200, filed.text
    assert filed.json()["result"]["isError"] is False

    hidden = _mcp(
        client,
        "tools/call",
        {"name": "inquire", "arguments": {"agent_id": "shopper-01", "purpose_code": "payment_authorization"}},
        token=test_merchant,
    )
    assert hidden.status_code == 200, hidden.text
    assert hidden.json()["result"]["isError"] is True
    assert "agent was not found" in hidden.json()["result"]["content"][0]["text"]

    test_agent = private_key_from_seed(hashlib.sha256(b"bureau-agent-sandbox").digest())
    test_registered = client.post(
        "/v1/agents",
        headers=_auth(test_operator),
        json={
            "agent_id": "shopper-01",
            "principal_id": "prn_person",
            "public_key": test_agent.public.to_jwk(),
            "verification_level": "operator_verified",
        },
    )
    assert test_registered.status_code == 200, test_registered.text
    test_view = _mcp(
        client,
        "tools/call",
        {"name": "inquire", "arguments": {"agent_id": "shopper-01", "purpose_code": "payment_authorization"}},
        token=test_merchant,
    )
    assert test_view.status_code == 200, test_view.text
    structured = test_view.json()["result"]["structuredContent"]
    assert structured["agent"]["status"] == "active"
    assert structured["incidents"]["counts"]["fraud_incident"] == 0
    live_view = _mcp(
        client,
        "tools/call",
        {"name": "inquire", "arguments": {"agent_id": "shopper-01", "purpose_code": "fraud_investigation"}},
        token=live_merchant,
    )
    assert live_view.json()["result"]["structuredContent"]["incidents"]["counts"]["fraud_incident"] == 1
    assert client.get("/v1/agents/shopper-01", headers=_auth(live_operator)).json()["score"] < client.get(
        "/v1/agents/shopper-01", headers=_auth(test_operator)
    ).json()["score"]

    revocations = _mcp(client, "tools/call", {"name": "check_revocation", "arguments": {"agent_id": "shopper-01"}}, token=test_merchant)
    assert revocations.status_code == 200, revocations.text
    assert revocations.json()["result"]["structuredContent"]["agent"]["environment"] == "test"
    assert revocations.json()["result"]["structuredContent"]["revocations"] == []

    receipt = _mcp(client, "tools/call", {"name": "fetch_signed_receipt", "arguments": {"sequence": 1}}, token=live_merchant)
    assert receipt.status_code == 200, receipt.text
    assert "entry" in receipt.json()["result"]["structuredContent"]
    missing = _mcp(client, "tools/call", {"name": "fetch_signed_receipt", "arguments": {"sequence": 999999}}, token=live_merchant)
    assert missing.json()["result"]["isError"] is True
    assert missing.json()["result"]["content"][0]["text"] == "a signed log entry is not available"

    audit = client.app.state.bureau.repo.list_audit(merchant["org_id"])
    assert audit
    assert live_merchant not in str(audit)
    assert test_merchant not in str(audit)

    limited = _client(verify_rate_limit_per_minute=1)
    limited_org = _org(limited, "Techstore", "merchant")
    limited_key = _key(limited, limited_org["org_id"], "shop")
    first = _mcp(limited, "tools/call", {"name": "verify_agent", "arguments": {"agent_id": "shopper-01", "action": {}}}, token=limited_key)
    assert first.status_code == 200
    second = _mcp(limited, "tools/call", {"name": "verify_agent", "arguments": {"agent_id": "shopper-01", "action": {}}}, token=limited_key)
    assert second.status_code == 429
    assert second.json()["error"]["message"] == "rate limit exceeded"
    assert limited_key not in second.text

    sandbox = _client(deployment_env="sandbox")
    sandbox_org = _org(sandbox, "Harbor Agents", "agent_operator")
    sandbox_key = _key(sandbox, sandbox_org["org_id"], "sandbox")
    assert sandbox_key.startswith("gab_test_")
    assert _mcp(sandbox, "tools/list", token=sandbox_key).status_code == 200
    sandbox.app.state.bureau.repo.create_key(
        {
            "key_id": "key_live_fixture",
            "org_id": sandbox_org["org_id"],
            "name": "live fixture",
            "prefix": "ffffeeee",
            "environment": "live",
            "secret_hash": token_hash("gab_ffffeeee_fixture"),
            "scopes": ["registry:read", "verify", "inquire", "report"],
            "created_at": "2026-10-16T00:00:00Z",
            "revoked_at": None,
            "rotated_from": None,
        }
    )
    refused = _mcp(sandbox, "tools/list", token="gab_ffffeeee_fixture")
    assert refused.status_code == 403
    assert "gab_ffffeeee_fixture" not in refused.text

    page = client.get("/docs/mcp")
    assert page.status_code == 200
    assert "2026-07-28" in page.text
    assert "gab_test_" in page.text
    assert "agent bureau" in page.text.lower()
    assert "PolyForm" in page.text
    folded = page.text.lower().replace("tools/call", "")
    assert "call" not in folded
    assert "open source" not in folded
    assert "credit bureau" not in folded
