# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Remove a signed-in portal principal from the live database in this process.

SYNTHETIC TEST DATA. Local only. A backup or a restore can bring the data back.
An embedded seal string cannot be shredded. Another process may hold the data
key for up to 300 seconds.
"""

from __future__ import annotations

import psycopg

from kata_intent import generate_keypair
from kata_service.asgi import create_app
from kata_service.keys import EnvKeyProvider, InProcessDekStore, open_stored, seal_detached
from kata_service.settings import settings_from_env

from soft_passkey import assertion_for, bind_device
from test_bureau import _action, _auth
from test_portal_devices import _portal_client, _portal_token
from test_postgres_path import _database_url, _reset

_LIMITS = [
    "Removed from the live database in this process.",
    "A backup or a restore can bring the data back.",
    "An embedded seal string cannot be shredded.",
    "Another process may hold the data key for up to 300 seconds.",
]


def test_signed_in_principal_is_removed_and_a_repeat_is_401():
    client = _portal_client(rate_limit_per_minute=1000)
    other = generate_keypair("EdDSA")
    registered = client.post(
        "/v1/agents",
        headers=_auth(client.operator_key),
        json={
            "agent_id": "shopper-02",
            "principal_id": "prn_other",
            "principal_email": "other@example.com",
            "public_key": other.public.to_jwk(),
            "verification_level": "operator_verified",
        },
    )
    assert registered.status_code == 200, registered.text
    token = _portal_token(client)
    soft = bind_device(client, token, "Phone")
    allowed = client.post(
        "/v1/verify",
        headers=_auth(client.merchant_key),
        json={"agent_id": "shopper-01", "action": _action(10, "act_subject")},
    )
    assert allowed.status_code == 200, allowed.text
    assert allowed.json()["verdict"] == "ALLOW"
    evidence = "sha256:" + "ab" * 32
    filed = client.post(
        "/v1/reports",
        headers=_auth(client.merchant_key),
        json={
            "agent_id": "shopper-01",
            "kind": "fraud_incident",
            "evidence_hash": evidence,
            "summary": "Synthetic report",
        },
    )
    assert filed.status_code == 200, filed.text
    report_id = filed.json()["report_id"]
    inquiry = client.post(
        "/v1/inquiries",
        headers=_auth(client.merchant_key),
        json={"agent_id": "shopper-01", "purpose_code": "payment_authorization"},
    )
    assert inquiry.status_code == 200, inquiry.text
    inquiry_id = inquiry.json()["inquiry_id"]
    subscribed = client.post(
        "/v1/subscriptions",
        headers=_auth(client.merchant_key),
        json={"agent_id": "shopper-01", "webhook_url": "https://merchant.example/hooks/gab"},
    )
    assert subscribed.status_code == 200, subscribed.text
    org_id = client.app.state.bureau.repo.get_agent("shopper-01")["operator_org_id"]
    emailed = client.post(
        f"/v1/orgs/{org_id}/emails",
        headers=_auth("admin-test-token"),
        json={"email": "ops@example.com"},
    )
    assert emailed.status_code == 200, emailed.text
    pushed = client.post(
        "/v1/portal/push",
        headers=_auth(token),
        json={"consent": True, "endpoint": "https://push.example/device", "keys": {"p256dh": "abc", "auth": "def"}},
    )
    assert pushed.status_code == 200, pushed.text
    dispute = client.post(
        "/v1/portal/disputes",
        headers=_auth(token),
        json={"report_id": report_id, "statement": "Synthetic statement", "assertion": assertion_for(client, token, soft)},
    )
    assert dispute.status_code == 200, dispute.text
    dispute_id = dispute.json()["dispute_id"]
    bureau = client.app.state.bureau
    allows = bureau.repo.agreement_allow_count("agr_test", "int_laptop", None, "2026-12-31T23:59:59Z")
    assert allows >= 1

    before = len(bureau.repo.audit)
    missing = client.request(
        "DELETE",
        "/v1/portal/subject",
        headers=_auth(token),
        json={},
    )
    assert missing.status_code == 401
    assert bureau.repo.login_by_email("owner@example.com")["principal_id"] == "prn_owner"
    assert len(bureau.repo.audit) == before

    removed = client.request(
        "DELETE",
        "/v1/portal/subject",
        headers=_auth(token),
        json={"assertion": assertion_for(client, token, soft)},
    )
    assert removed.status_code == 200, removed.text
    body = removed.json()
    assert body["removed"] is True
    assert body["limits"] == _LIMITS
    assert "deleted" not in removed.text
    assert "erased" not in removed.text
    subject_rows = [row for row in bureau.repo.audit if row["path"] == "/v1/portal/subject"]
    assert len(subject_rows) == 1
    assert subject_rows[0]["method"] == "DELETE"
    assert subject_rows[0]["status"] == 200
    assert subject_rows[0]["agent_id"] is None
    assert "owner@example.com" not in str(subject_rows[0])
    assert "prn_owner" not in str(subject_rows[0])

    assert bureau.repo.login_by_email("owner@example.com") is None
    assert bureau.repo.login_by_email("other@example.com")["principal_id"] == "prn_other"
    assert bureau.repo.org_login_by_email("ops@example.com")["org_id"] == org_id
    assert not any(
        item.get("kind") == "portal" and item.get("subject_id") == "prn_owner" for item in bureau.repo.sessions.values()
    )
    assert bureau.repo.list_passkeys("prn_owner") == []
    assert bureau.repo.list_push("prn_owner") == []
    agent = client.get("/v1/agents/shopper-01", headers=_auth(client.operator_key))
    assert agent.status_code == 200, agent.text
    assert agent.json()["status"] == "revoked"
    other_agent = client.get("/v1/agents/shopper-02", headers=_auth(client.operator_key))
    assert other_agent.json()["status"] == "active"
    intents = client.get("/v1/agents/shopper-01/intents", headers=_auth(client.operator_key))
    assert intents.status_code == 200, intents.text
    assert intents.json()[0]["status"] == "active"
    assert bureau.repo.agreement_allow_count("agr_test", "int_laptop", None, "2026-12-31T23:59:59Z") == allows
    reports = client.get("/v1/agents/shopper-01/reports", headers=_auth(client.merchant_key))
    assert reports.json()["reports"][0]["summary"] == "Synthetic report"
    subs = client.get("/v1/subscriptions", headers=_auth(client.merchant_key))
    assert subs.json()[0]["webhook_url"] == "https://merchant.example/hooks/gab"
    queued = client.get("/v1/admin/disputes", headers=_auth("admin-test-token"))
    kept = [item for item in queued.json() if item["dispute_id"] == dispute_id][0]
    assert kept["statement"] == ""
    assert kept["principal_id"] is None
    assert kept["status"] == "open"
    cleared = [item for item in bureau.repo.inquiries if item["inquiry_id"] == inquiry_id][0]
    assert cleared["principal_id"] is None
    assert cleared["org_id"]
    assert "score" in agent.json()

    after = len(bureau.repo.audit)
    again = client.request("DELETE", "/v1/portal/subject", headers=_auth(token), json={})
    assert again.status_code == 401
    assert len(bureau.repo.audit) == after
    assert len([row for row in bureau.repo.audit if row["path"] == "/v1/portal/subject"]) == 1


def test_an_embedded_seal_still_opens_after_the_live_key_is_removed():
    client = _portal_client(rate_limit_per_minute=1000)
    token = _portal_token(client)
    soft = bind_device(client, token, "Phone")
    provider = EnvKeyProvider({}, master_key=b"\x11" * 32, subject_key=b"\x22" * 32)
    store = InProcessDekStore(b"\x22" * 32)
    bureau = client.app.state.bureau
    bureau.key_provider = provider
    bureau.dek_store = store
    embedded = provider.seal(b"SYNTHETIC TEST DATA", subject_id="prn_owner")
    detached, wrapped = seal_detached(provider, b"SYNTHETIC TEST DATA", subject_id="prn_owner", store=store)
    removed = client.request(
        "DELETE",
        "/v1/portal/subject",
        headers=_auth(token),
        json={"assertion": assertion_for(client, token, soft)},
    )
    assert removed.status_code == 200, removed.text
    assert provider.unseal(embedded, subject_id="prn_owner") == b"SYNTHETIC TEST DATA"
    assert store.get("prn_owner") is None
    try:
        open_stored(provider, detached, subject_id="prn_owner", store=store)
    except Exception as exc:
        assert type(exc).__name__ == "KeyCustodyError"
    else:
        raise AssertionError("open_stored still read a wrapped key")


def test_postgres_removal_keeps_one_audit_row_and_clears_sandbox_copies():
    url = _database_url()
    _reset(url)
    from fastapi.testclient import TestClient
    from test_bureau import _register

    app = TestClient(
        create_app(
            settings_from_env(
                {
                    "DATABASE_URL": url,
                    "DATABASE_URL_UNPOOLED": url,
                    "GAB_ADMIN_TOKEN": "synthetic-admin-token",
                    "GAB_DEV_MAILBOX": "1",
                    "GAB_RATE_LIMIT_PER_MINUTE": "1000000",
                    "GAB_VERIFY_RATE_LIMIT_PER_MINUTE": "1000000",
                    "GAB_ENV": "sandbox",
                }
            )
        )
    )
    operator = app.post(
        "/v1/orgs",
        headers=_auth("synthetic-admin-token"),
        json={"name": "Harbor Agents", "org_type": "agent_operator"},
    )
    assert operator.status_code == 200, operator.text
    merchant = app.post(
        "/v1/orgs",
        headers=_auth("synthetic-admin-token"),
        json={"name": "Techstore", "org_type": "merchant"},
    )
    assert merchant.status_code == 200, merchant.text
    operator_key = app.post(
        f"/v1/orgs/{operator.json()['org_id']}/keys",
        headers=_auth("synthetic-admin-token"),
        json={"name": "primary", "environment": "test"},
    ).json()["token"]
    merchant_key = app.post(
        f"/v1/orgs/{merchant.json()['org_id']}/keys",
        headers=_auth("synthetic-admin-token"),
        json={"name": "primary", "environment": "test"},
    ).json()["token"]
    _register(app, operator_key, principal_id="prn_owner", principal_email="owner@example.com")
    app.operator_key = operator_key
    app.merchant_key = merchant_key
    token = _portal_token(app)
    soft = bind_device(app, token, "Phone")
    with psycopg.connect(url) as conn:
        conn.execute(
            """
            INSERT INTO gab_sandbox.gab_agents (
              agent_id, operator_org_id, principal_id, status, verification_level, algorithm,
              fingerprint, public_key, created_at, updated_at, score, score_reasons, cold_start
            ) VALUES (
              'shopper-sandbox', %s, 'prn_owner', 'active', 'operator_verified', 'EdDSA',
              'fp-sandbox', '{}', '2026-10-18T00:00:00Z', '2026-10-18T00:00:00Z', 0, '[]', 1
            )
            """,
            (operator.json()["org_id"],),
        )
        conn.execute(
            """
            INSERT INTO gab_sandbox.gab_disputes (
              dispute_id, report_id, principal_id, statement, status, created_at, updated_at
            ) VALUES (
              'dsp_sandbox', 'rpt_sandbox', 'prn_owner', 'keep the row', 'open',
              '2026-10-18T00:00:00Z', '2026-10-18T00:00:00Z'
            )
            """
        )
        conn.execute(
            """
            INSERT INTO gab_sandbox.gab_inquiries (
              inquiry_id, org_id, agent_id, principal_id, purpose_code, at
            ) VALUES (
              'inq_sandbox', %s, 'shopper-sandbox', 'prn_owner', 'payment_authorization',
              '2026-10-18T00:00:00Z'
            )
            """,
            (merchant.json()["org_id"],),
        )
    removed = app.request(
        "DELETE",
        "/v1/portal/subject",
        headers=_auth(token),
        json={"assertion": assertion_for(app, token, soft)},
    )
    assert removed.status_code == 200, removed.text
    chain = app.app.state.bureau.repo.audit_chain()
    assert chain["ok"] is True
    with psycopg.connect(url) as conn:
        subject_rows = conn.execute(
            "SELECT method, path, status, agent_id FROM gab_audit WHERE path = '/v1/portal/subject'"
        ).fetchall()
        login = conn.execute("SELECT email FROM gab_logins WHERE principal_id = 'prn_owner'").fetchone()
        agent = conn.execute(
            "SELECT status FROM gab_agents WHERE agent_id = 'shopper-01' AND principal_id = 'prn_owner'"
        ).fetchone()
        sandbox_agent = conn.execute(
            "SELECT status FROM gab_sandbox.gab_agents WHERE agent_id = 'shopper-sandbox'"
        ).fetchone()
        sandbox_dispute = conn.execute(
            "SELECT statement, principal_id FROM gab_sandbox.gab_disputes WHERE dispute_id = 'dsp_sandbox'"
        ).fetchone()
        sandbox_inquiry = conn.execute(
            "SELECT principal_id FROM gab_sandbox.gab_inquiries WHERE inquiry_id = 'inq_sandbox'"
        ).fetchone()
    assert subject_rows == [("DELETE", "/v1/portal/subject", 200, None)]
    assert login is None
    assert agent[0] == "revoked"
    assert sandbox_agent[0] == "revoked"
    assert sandbox_dispute == ("", None)
    assert sandbox_inquiry == (None,)
    again = app.request("DELETE", "/v1/portal/subject", headers=_auth(token), json={})
    assert again.status_code == 401
    with psycopg.connect(url) as conn:
        after = conn.execute("SELECT count(*) FROM gab_audit WHERE path = '/v1/portal/subject'").fetchone()
    assert after[0] == 1
    chain_after = app.app.state.bureau.repo.audit_chain()
    assert chain_after["ok"] is True
    assert chain_after["rows"] == chain["rows"]
