# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Malformed actions, public text files, and the audit environment column."""

from __future__ import annotations

import json
from pathlib import Path

from tests.test_bureau import _action, _agreement, _auth, _client, _key, _org, _register


def _ready():
    client = _client()
    operator = _org(client, "Harbor Agents", "agent_operator")
    merchant = _org(client, "Techstore", "merchant")
    operator_key = _key(client, operator["org_id"])
    merchant_key = _key(client, merchant["org_id"])
    _register(client, operator_key)
    stored = client.post(
        "/v1/agents/shopper-01/intents",
        headers={**_auth(operator_key), "Content-Type": "application/json"},
        content=_agreement().to_json(),
    )
    assert stored.status_code == 200, stored.text
    return client, operator_key, merchant_key


def test_a_non_numeric_amount_is_denied():
    client, _operator_key, merchant_key = _ready()
    action = _action(10)
    action["amount"] = "abc"
    checked = client.post("/v1/verify", headers=_auth(merchant_key), json={"agent_id": "shopper-01", "action": action})
    assert checked.status_code == 200, checked.text
    body = checked.json()
    assert body["verdict"] == "DENY"
    assert "ACTION_MALFORMED" in body["reasons"]


def test_a_deeply_nested_action_is_rejected():
    client, _operator_key, merchant_key = _ready()
    node: object = {"leaf": 1}
    for _ in range(40):
        node = {"down": node}
    action = _action(10)
    action["context"] = node
    checked = client.post("/v1/verify", headers=_auth(merchant_key), json={"agent_id": "shopper-01", "action": action})
    assert checked.status_code == 400, checked.text
    assert checked.json()["error"] == "document is nested too deeply"


def test_loopback_webhook_urls_are_rejected():
    client, _operator_key, merchant_key = _ready()
    for url in ("http://localhost/hook", "https://127.0.0.1/hook", "https://localhost/hook"):
        rejected = client.post(
            "/v1/subscriptions",
            headers=_auth(merchant_key),
            json={"agent_id": "shopper-01", "webhook_url": url},
        )
        assert rejected.status_code == 400, rejected.text
        assert rejected.json()["error"] == "webhook_url must be https"
    accepted = client.post(
        "/v1/subscriptions",
        headers=_auth(merchant_key),
        json={"agent_id": "shopper-01", "webhook_url": "https://merchant.example/hooks/gab"},
    )
    assert accepted.status_code == 200, accepted.text


def test_public_text_files_name_the_mcp_endpoint():
    client = _client()
    robots = client.get("/robots.txt")
    llms = client.get("/llms.txt")
    assert robots.status_code == 200
    assert llms.status_code == 200
    assert robots.headers["content-type"].startswith("text/plain")
    assert llms.headers["content-type"].startswith("text/plain")
    for page in (robots.text, llms.text):
        assert "/mcp" in page
        assert "/docs" in page
        assert "/status" in page
        assert "call" not in page.lower()
        assert "open source" not in page.lower()
        assert "credit bureau" not in page.lower()
    assert "agent bureau" in llms.text.lower()
    assert "technology company" in llms.text.lower()
    assert "PolyForm Noncommercial" in llms.text
    assert "5 tools" in llms.text
    assert "streamable HTTP" in llms.text
    assert "gab_test_" in llms.text
    assert "Retry-After" in llms.text
    assert "assumed mapping" in llms.text
    assert "does not host checkout" in llms.text
    for banned in ("316 checks", "latest test round", "malformed input", "security headers", "synthetic test data"):
        assert banned not in llms.text.lower()


def test_vercel_headers_keep_the_site_assets():
    path = Path(__file__).resolve().parents[2] / "vercel.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    groups = document["headers"]
    assert groups[0]["source"] == "/(.*)"
    found = {item["key"]: item["value"] for item in groups[0]["headers"]}
    assert found["X-Content-Type-Options"] == "nosniff"
    assert found["X-Frame-Options"] == "DENY"
    assert found["Referrer-Policy"] == "strict-origin-when-cross-origin"
    assert "camera=()" in found["Permissions-Policy"]
    policy = found["Content-Security-Policy"]
    assert "default-src 'self'" in policy
    assert "'unsafe-inline'" in policy
    assert "media-src 'self'" in policy
    assert "https://cdn.jsdelivr.net" in policy


def test_audit_rows_record_the_key_environment():
    client = _client(dev_mailbox=True)
    operator = _org(client, "Harbor Agents", "agent_operator")
    live = _key(client, operator["org_id"], "live")
    issued = client.post(
        f"/v1/orgs/{operator['org_id']}/keys",
        headers=_auth("admin-test-token"),
        json={"name": "sandbox", "environment": "test"},
    )
    assert issued.status_code == 200, issued.text
    test_key = issued.json()["token"]
    assert test_key.startswith("gab_test_")
    _register(client, live, principal_email="owner@example.com")
    assert client.get("/v1/agents/shopper-01", headers=_auth(live)).status_code == 200
    assert client.get("/v1/agents/shopper-01", headers=_auth(test_key)).status_code == 404
    live_rows = client.get("/v1/audit", headers=_auth(live))
    test_rows = client.get("/v1/audit", headers=_auth(test_key))
    assert live_rows.status_code == 200, live_rows.text
    assert test_rows.status_code == 200, test_rows.text
    assert live_rows.json()
    assert test_rows.json()
    assert all(row["environment"] == "live" for row in live_rows.json())
    assert all(row["environment"] == "test" for row in test_rows.json())
    assert any(row["path"] == "/v1/agents/shopper-01" for row in live_rows.json())
    assert any(row["path"] == "/v1/agents/shopper-01" for row in test_rows.json())
    link = client.post("/v1/portal/magic-link", json={"email": "owner@example.com"})
    assert link.status_code == 200, link.text
    session = client.post("/v1/sessions", json={"token": client.app.state.bureau.dev_mailbox[-1]["token"]})
    assert session.status_code == 200, session.text
    portal = client.get("/v1/audit", headers=_auth(session.json()["token"]))
    assert portal.status_code == 403
    assert portal.json()["error"] == "missing scope"


def test_postgres_rejects_a_control_character_and_stores_the_audit_environment():
    from tests.test_postgres_path import _database_url, _reset

    url = _database_url()
    _reset(url)
    client = _client(database_url=url, schema_url=url)
    operator = _org(client, "Harbor Agents", "agent_operator")
    live = _key(client, operator["org_id"], "live")
    issued = client.post(
        f"/v1/orgs/{operator['org_id']}/keys",
        headers=_auth("admin-test-token"),
        json={"name": "sandbox", "environment": "test"},
    )
    assert issued.status_code == 200, issued.text
    test_key = issued.json()["token"]
    rejected = client.post(
        "/v1/verify",
        headers=_auth(live),
        json={"agent_id": "shopper\x00", "action": {"amount": "abc"}},
    )
    assert rejected.status_code == 400, rejected.text
    assert "control character" in rejected.json()["error"]
    assert client.get("/v1/agents/shopper-01", headers=_auth(live)).status_code == 404
    assert client.get("/v1/agents/shopper-01", headers=_auth(test_key)).status_code == 404
    live_rows = client.get("/v1/audit", headers=_auth(live)).json()
    test_rows = client.get("/v1/audit", headers=_auth(test_key)).json()
    assert live_rows and all(row["environment"] == "live" for row in live_rows)
    assert test_rows and all(row["environment"] == "test" for row in test_rows)
    assert any(row["path"] == "/v1/agents/shopper-01" for row in live_rows)
    assert any(row["path"] == "/v1/agents/shopper-01" for row in test_rows)
    versions = client.app.state.bureau.repo.migration_versions()
    assert "008_audit_environment.sql" in versions


def _nested(levels: int) -> dict:
    node: dict = {"leaf": 1}
    for _ in range(levels):
        node = {"down": node}
    return node


def test_a_deep_body_without_an_agent_id_is_rejected():
    client, _operator_key, merchant_key = _ready()
    deep = _nested(40)
    for path in ("/v1/verify", "/v1/reports", "/v1/inquiries", "/v1/subscriptions"):
        rejected = client.post(path, headers=_auth(merchant_key), json=deep)
        assert rejected.status_code == 400, (path, rejected.text)
        assert rejected.json()["error"] == "document is nested too deeply"
    missing = client.post("/v1/verify", headers=_auth(merchant_key), json={"action": _action(10)})
    assert missing.status_code == 404
    assert missing.json()["error"] == "agent was not found"
    action = _action(10)
    action["context"] = _nested(30)
    held = client.post("/v1/verify", headers=_auth(merchant_key), json={"agent_id": "shopper-01", "action": action})
    assert "document is nested too deeply" not in held.text
