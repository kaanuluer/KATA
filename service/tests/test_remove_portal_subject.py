# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Remove a signed-in portal principal from the live database in this process.

SYNTHETIC TEST DATA. Local only. A backup or a restore can bring the data back.
An embedded seal string cannot be shredded. Another process may hold the data
key for up to 300 seconds.
"""

from __future__ import annotations

import base64

import psycopg

from kata_intent import generate_keypair
from kata_service.asgi import create_app
from kata_service.bureau import email_hash
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
    assert body["deleted"] is True
    assert body["limits"] == _LIMITS
    for sentence in body["limits"]:
        assert "erased" not in sentence
        assert "deleted" not in sentence.lower()
    assert "prn_owner" in bureau.repo.principals
    assert "prn_other" in bureau.repo.principals
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


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _postgres_portal(*, master_key: bytes | None = None, subject_key: bytes | None = None):
    from fastapi.testclient import TestClient
    from test_bureau import _register

    url = _database_url()
    _reset(url)
    env = {
        "DATABASE_URL": url,
        "DATABASE_URL_UNPOOLED": url,
        "GAB_ADMIN_TOKEN": "synthetic-admin-token",
        "GAB_DEV_MAILBOX": "1",
        "GAB_RATE_LIMIT_PER_MINUTE": "1000000",
        "GAB_VERIFY_RATE_LIMIT_PER_MINUTE": "1000000",
        "GAB_ENV": "sandbox",
    }
    if master_key is not None:
        env["GAB_MASTER_KEY"] = _b64(master_key)
    if subject_key is not None:
        env["GAB_SUBJECT_REF_KEY"] = _b64(subject_key)
    app = TestClient(create_app(settings_from_env(env)))
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
    other = generate_keypair("EdDSA")
    registered = app.post(
        "/v1/agents",
        headers=_auth(operator_key),
        json={
            "agent_id": "shopper-02",
            "principal_id": "prn_other",
            "principal_email": "other@example.com",
            "public_key": other.public.to_jwk(),
            "verification_level": "operator_verified",
        },
    )
    assert registered.status_code == 200, registered.text
    app.operator_key = operator_key
    app.merchant_key = merchant_key
    token = _portal_token(app)
    soft = bind_device(app, token, "Phone")
    return app, url, token, soft, operator.json()["org_id"], merchant.json()["org_id"]


def test_postgres_removal_keeps_one_audit_row_and_clears_sandbox_copies():
    app, url, token, soft, operator_id, merchant_id = _postgres_portal(
        master_key=b"\x11" * 32, subject_key=b"\x22" * 32
    )
    store = app.app.state.bureau.dek_store
    assert store is not None
    store.put("prn_owner", b"synthetic-wrapped-owner")
    store.put("prn_other", b"synthetic-wrapped-other")
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
            (operator_id,),
        )
        conn.execute(
            """
            INSERT INTO gab_magic_links (token_hash, kind, subject_hash, expires_at)
            VALUES ('tok_owner', 'portal', %s, '2026-12-31T23:59:59Z'),
                   ('tok_other', 'portal', %s, '2026-12-31T23:59:59Z')
            """,
            (email_hash("owner@example.com"), email_hash("other@example.com")),
        )
        conn.execute(
            """
            INSERT INTO gab_webauthn_challenges (
              challenge_id, principal_id, kind, challenge, rp_id, origin, expires_at
            ) VALUES
              ('ch_owner', 'prn_owner', 'assert', 'synthetic-owner', 'localhost', 'http://testserver', '2026-12-31T23:59:59Z'),
              ('ch_other', 'prn_other', 'assert', 'synthetic-other', 'localhost', 'http://testserver', '2026-12-31T23:59:59Z')
            """
        )
        conn.execute(
            """
            INSERT INTO gab_approvals (
              approval_id, principal_id, action_hash, status, expires_at, created_at
            ) VALUES
              ('apr_owner', 'prn_owner', 'synthetic-owner', 'pending', '2026-12-31T23:59:59Z', '2026-10-18T00:00:00Z'),
              ('apr_other', 'prn_other', 'synthetic-other', 'pending', '2026-12-31T23:59:59Z', '2026-10-18T00:00:00Z')
            """
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
            (merchant_id,),
        )
    removed = app.request(
        "DELETE",
        "/v1/portal/subject",
        headers=_auth(token),
        json={"assertion": assertion_for(app, token, soft)},
    )
    assert removed.status_code == 200, removed.text
    assert removed.json()["deleted"] is True
    assert removed.json()["limits"] == _LIMITS
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
        principal = conn.execute(
            "SELECT principal_id FROM gab_principals WHERE principal_id = 'prn_owner'"
        ).fetchone()
        other_principal = conn.execute(
            "SELECT principal_id FROM gab_principals WHERE principal_id = 'prn_other'"
        ).fetchone()
        other_login = conn.execute("SELECT email FROM gab_logins WHERE principal_id = 'prn_other'").fetchone()
        other_agent = conn.execute(
            "SELECT status FROM gab_agents WHERE agent_id = 'shopper-02' AND principal_id = 'prn_other'"
        ).fetchone()
        owner_magic = conn.execute(
            "SELECT count(*) FROM gab_magic_links WHERE subject_hash = %s",
            (email_hash("owner@example.com"),),
        ).fetchone()
        other_magic = conn.execute(
            "SELECT count(*) FROM gab_magic_links WHERE subject_hash = %s",
            (email_hash("other@example.com"),),
        ).fetchone()
        owner_challenges = conn.execute(
            "SELECT count(*) FROM gab_webauthn_challenges WHERE principal_id = 'prn_owner'"
        ).fetchone()
        other_challenges = conn.execute(
            "SELECT count(*) FROM gab_webauthn_challenges WHERE principal_id = 'prn_other'"
        ).fetchone()
        owner_approvals = conn.execute(
            "SELECT count(*) FROM gab_approvals WHERE principal_id = 'prn_owner'"
        ).fetchone()
        other_approvals = conn.execute(
            "SELECT count(*) FROM gab_approvals WHERE principal_id = 'prn_other'"
        ).fetchone()
    assert subject_rows == [("DELETE", "/v1/portal/subject", 200, None)]
    assert login is None
    assert agent[0] == "revoked"
    assert sandbox_agent[0] == "revoked"
    assert sandbox_dispute == ("", None)
    assert sandbox_inquiry == (None,)
    assert principal == ("prn_owner",)
    assert other_principal == ("prn_other",)
    assert other_login[0] == "other@example.com"
    assert other_agent[0] == "active"
    assert owner_magic[0] == 0
    assert other_magic[0] == 1
    assert owner_challenges[0] == 0
    assert other_challenges[0] == 1
    assert owner_approvals[0] == 0
    assert other_approvals[0] == 1
    assert store.get("prn_owner") is None
    assert store.get("prn_other") == b"synthetic-wrapped-other"
    again = app.request("DELETE", "/v1/portal/subject", headers=_auth(token), json={})
    assert again.status_code == 401
    with psycopg.connect(url) as conn:
        after = conn.execute("SELECT count(*) FROM gab_audit WHERE path = '/v1/portal/subject'").fetchone()
    assert after[0] == 1
    chain_after = app.app.state.bureau.repo.audit_chain()
    assert chain_after["ok"] is True
    assert chain_after["rows"] == chain["rows"]


def _delete_subject(client, token, soft):
    return client.request(
        "DELETE",
        "/v1/portal/subject",
        headers=_auth(token),
        json={"assertion": assertion_for(client, token, soft)},
    )


def test_removal_warns_when_no_key_provider_is_configured(caplog):
    client = _portal_client(rate_limit_per_minute=1000)
    token = _portal_token(client)
    soft = bind_device(client, token, "Phone")
    with caplog.at_level("WARNING", logger="kata_service.bureau"):
        removed = _delete_subject(client, token, soft)
    assert removed.status_code == 200, removed.text
    assert removed.json()["deleted"] is True
    assert any("no key provider is configured" in record.message for record in caplog.records)
    assert "prn_owner" in client.app.state.bureau.repo.principals


def test_removal_warns_when_the_data_key_store_is_not_configured(caplog):
    client = _portal_client(rate_limit_per_minute=1000)
    token = _portal_token(client)
    soft = bind_device(client, token, "Phone")
    bureau = client.app.state.bureau
    bureau.key_provider = EnvKeyProvider({}, master_key=b"\x11" * 32)
    bureau.dek_store = None
    with caplog.at_level("WARNING", logger="kata_service.bureau"):
        removed = _delete_subject(client, token, soft)
    assert removed.status_code == 200, removed.text
    assert any("no data key store is configured" in record.message for record in caplog.records)


def test_a_shred_failure_leaves_the_session_for_a_retry():
    client = _portal_client(rate_limit_per_minute=1000)
    token = _portal_token(client)
    soft = bind_device(client, token, "Phone")
    provider = EnvKeyProvider({}, master_key=b"\x11" * 32, subject_key=b"\x22" * 32)
    store = InProcessDekStore(b"\x22" * 32)
    store.put("prn_owner", b"synthetic-wrapped-owner")
    bureau = client.app.state.bureau
    bureau.key_provider = provider
    bureau.dek_store = store

    def fail(subject_id):
        raise RuntimeError("synthetic shred failure")

    store.destroy = fail
    failed = _delete_subject(client, token, soft)
    assert failed.status_code == 503
    assert failed.json()["error"] == "The subject data key was not removed from the live store in this process."
    assert bureau.repo.login_by_email("owner@example.com")["principal_id"] == "prn_owner"
    assert bureau.repo.get_agent("shopper-01")["status"] == "active"
    assert store.get("prn_owner") == b"synthetic-wrapped-owner"
    assert not any(row["path"] == "/v1/portal/subject" for row in bureau.repo.audit)
    del store.destroy
    removed = _delete_subject(client, token, soft)
    assert removed.status_code == 200, removed.text
    assert removed.json()["deleted"] is True
    assert store.get("prn_owner") is None
    assert bureau.repo.login_by_email("owner@example.com") is None
    assert bureau.repo.get_agent("shopper-01")["status"] == "revoked"
    assert len([row for row in bureau.repo.audit if row["path"] == "/v1/portal/subject"]) == 1


def test_an_audit_failure_rolls_the_removal_back():
    import kata_service.bureau as bureau_mod

    client = _portal_client(rate_limit_per_minute=1000)
    token = _portal_token(client)
    soft = bind_device(client, token, "Phone")
    bureau = client.app.state.bureau
    real = bureau_mod._append_removal_audit

    def boom(rows, record):
        raise RuntimeError("synthetic audit failure")

    bureau_mod._append_removal_audit = boom
    try:
        failed = _delete_subject(client, token, soft)
    finally:
        bureau_mod._append_removal_audit = real
    assert failed.status_code == 500
    assert failed.json()["error"] == "subject removal did not finish"
    assert bureau.repo.login_by_email("owner@example.com")["principal_id"] == "prn_owner"
    assert bureau.repo.get_agent("shopper-01")["status"] == "active"
    assert not any(row["path"] == "/v1/portal/subject" for row in bureau.repo.audit)
    removed = _delete_subject(client, token, soft)
    assert removed.status_code == 200, removed.text
    assert bureau.repo.login_by_email("owner@example.com") is None
    assert bureau.repo.get_agent("shopper-01")["status"] == "revoked"
    assert len([row for row in bureau.repo.audit if row["path"] == "/v1/portal/subject"]) == 1


def test_a_master_key_without_a_subject_ref_key_still_serves_postgres():
    from fastapi.testclient import TestClient

    url = _database_url()
    _reset(url)
    app = TestClient(
        create_app(
            settings_from_env(
                {
                    "DATABASE_URL": url,
                    "DATABASE_URL_UNPOOLED": url,
                    "GAB_ADMIN_TOKEN": "synthetic-admin-token",
                    "GAB_ENV": "sandbox",
                    "GAB_MASTER_KEY": _b64(b"\x11" * 32),
                    "GAB_RATE_LIMIT_PER_MINUTE": "1000000",
                }
            )
        )
    )
    anonymous = app.get("/v1/agents/shopper-missing")
    assert anonymous.status_code == 401, anonymous.text
    admin = app.get("/v1/agents/shopper-missing", headers=_auth("synthetic-admin-token"))
    assert admin.status_code == 404, admin.text
    bureau = app.app.state.bureau
    assert bureau.key_provider is not None
    assert bureau.dek_store is None


def test_a_postgres_shred_failure_leaves_the_session_for_a_retry():
    app, url, token, soft, _operator_id, _merchant_id = _postgres_portal(
        master_key=b"\x11" * 32, subject_key=b"\x22" * 32
    )
    store = app.app.state.bureau.dek_store
    store.put("prn_owner", b"synthetic-wrapped-owner")

    def fail(subject_id):
        raise RuntimeError("synthetic shred failure")

    store.destroy = fail
    failed = _delete_subject(app, token, soft)
    assert failed.status_code == 503
    assert failed.json()["error"] == "The subject data key was not removed from the live store in this process."
    with psycopg.connect(url) as conn:
        login = conn.execute("SELECT email FROM gab_logins WHERE principal_id = 'prn_owner'").fetchone()
        agent = conn.execute(
            "SELECT status FROM gab_agents WHERE agent_id = 'shopper-01' AND principal_id = 'prn_owner'"
        ).fetchone()
        session = conn.execute(
            "SELECT count(*) FROM gab_sessions WHERE kind = 'portal' AND subject_id = 'prn_owner'"
        ).fetchone()
        audits = conn.execute("SELECT count(*) FROM gab_audit WHERE path = '/v1/portal/subject'").fetchone()
    assert login is not None
    assert agent[0] == "active"
    assert session[0] == 1
    assert audits[0] == 0
    assert store.get("prn_owner") == b"synthetic-wrapped-owner"
    del store.destroy
    removed = _delete_subject(app, token, soft)
    assert removed.status_code == 200, removed.text
    assert store.get("prn_owner") is None
    with psycopg.connect(url) as conn:
        login = conn.execute("SELECT email FROM gab_logins WHERE principal_id = 'prn_owner'").fetchone()
        agent = conn.execute(
            "SELECT status FROM gab_agents WHERE agent_id = 'shopper-01' AND principal_id = 'prn_owner'"
        ).fetchone()
        audits = conn.execute("SELECT count(*) FROM gab_audit WHERE path = '/v1/portal/subject'").fetchone()
    assert login is None
    assert agent[0] == "revoked"
    assert audits[0] == 1


def test_a_postgres_audit_failure_rolls_back_the_removal():
    import kata_service.bureau_pg as bureau_pg

    app, url, token, soft, operator_id, _merchant_id = _postgres_portal(
        master_key=b"\x11" * 32, subject_key=b"\x22" * 32
    )
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
            (operator_id,),
        )
    real = bureau_pg.audit_row_hash

    def flaky(prev, record):
        if record.get("path") == "/v1/portal/subject":
            raise RuntimeError("synthetic audit failure")
        return real(prev, record)

    bureau_pg.audit_row_hash = flaky
    try:
        failed = _delete_subject(app, token, soft)
    finally:
        bureau_pg.audit_row_hash = real
    assert failed.status_code == 500
    assert failed.json()["error"] == "subject removal did not finish"
    with psycopg.connect(url) as conn:
        login = conn.execute("SELECT email FROM gab_logins WHERE principal_id = 'prn_owner'").fetchone()
        agent = conn.execute(
            "SELECT status FROM gab_agents WHERE agent_id = 'shopper-01' AND principal_id = 'prn_owner'"
        ).fetchone()
        sandbox_agent = conn.execute(
            "SELECT status FROM gab_sandbox.gab_agents WHERE agent_id = 'shopper-sandbox'"
        ).fetchone()
        session = conn.execute(
            "SELECT count(*) FROM gab_sessions WHERE kind = 'portal' AND subject_id = 'prn_owner'"
        ).fetchone()
        audits = conn.execute("SELECT count(*) FROM gab_audit WHERE path = '/v1/portal/subject'").fetchone()
    assert login is not None
    assert agent[0] == "active"
    assert sandbox_agent[0] == "active"
    assert session[0] == 1
    assert audits[0] == 0
    assert app.app.state.bureau.repo.audit_chain()["ok"] is True
    removed = _delete_subject(app, token, soft)
    assert removed.status_code == 200, removed.text
    with psycopg.connect(url) as conn:
        login = conn.execute("SELECT email FROM gab_logins WHERE principal_id = 'prn_owner'").fetchone()
        agent = conn.execute(
            "SELECT status FROM gab_agents WHERE agent_id = 'shopper-01' AND principal_id = 'prn_owner'"
        ).fetchone()
        sandbox_agent = conn.execute(
            "SELECT status FROM gab_sandbox.gab_agents WHERE agent_id = 'shopper-sandbox'"
        ).fetchone()
        audits = conn.execute(
            "SELECT method, path, status FROM gab_audit WHERE path = '/v1/portal/subject'"
        ).fetchall()
    assert login is None
    assert agent[0] == "revoked"
    assert sandbox_agent[0] == "revoked"
    assert audits == [("DELETE", "/v1/portal/subject", 200)]
    assert app.app.state.bureau.repo.audit_chain()["ok"] is True


def test_a_revocation_alert_failure_still_returns_200(caplog):
    client = _portal_client(rate_limit_per_minute=1000)
    token = _portal_token(client)
    soft = bind_device(client, token, "Phone")
    bureau = client.app.state.bureau

    def boom(agent, kind, detail):
        raise RuntimeError("synthetic alert failure")

    bureau._alert = boom
    with caplog.at_level("ERROR", logger="kata_service.bureau"):
        removed = _delete_subject(client, token, soft)
    assert removed.status_code == 200, removed.text
    assert removed.json()["deleted"] is True
    assert bureau.repo.login_by_email("owner@example.com") is None
    assert bureau.repo.get_agent("shopper-01")["status"] == "revoked"
    assert not any(
        item.get("kind") == "portal" and item.get("subject_id") == "prn_owner" for item in bureau.repo.sessions.values()
    )
    assert any("revocation log or alert did not finish" in record.message for record in caplog.records)
    assert len([row for row in bureau.repo.audit if row["path"] == "/v1/portal/subject"]) == 1


def test_a_dek_row_without_a_provider_returns_503_and_keeps_the_session():
    client = _portal_client(rate_limit_per_minute=1000)
    token = _portal_token(client)
    soft = bind_device(client, token, "Phone")
    bureau = client.app.state.bureau
    store = InProcessDekStore(b"\x22" * 32)
    store.put("prn_owner", b"synthetic-wrapped-owner")
    bureau.key_provider = None
    bureau.dek_store = store
    blocked = _delete_subject(client, token, soft)
    assert blocked.status_code == 503
    assert blocked.json()["error"] == "The subject data key was not removed from the live store in this process."
    assert bureau.repo.login_by_email("owner@example.com")["principal_id"] == "prn_owner"
    assert bureau.repo.get_agent("shopper-01")["status"] == "active"
    assert any(item.get("kind") == "portal" and item.get("subject_id") == "prn_owner" for item in bureau.repo.sessions.values())
    assert not any(row["path"] == "/v1/portal/subject" for row in bureau.repo.audit)
    still = client.get("/v1/portal/agents", headers=_auth(token))
    assert still.status_code == 200, still.text
    bureau.dek_store = None
    removed = _delete_subject(client, token, soft)
    assert removed.status_code == 200, removed.text
    assert bureau.repo.login_by_email("owner@example.com") is None


def test_postgres_and_a_master_key_without_a_subject_ref_key_returns_503():
    app, url, token, soft, _operator_id, _merchant_id = _postgres_portal(master_key=b"\x11" * 32)
    assert app.app.state.bureau.master_key_configured is True
    assert app.app.state.bureau.dek_store is None
    blocked = _delete_subject(app, token, soft)
    assert blocked.status_code == 503
    assert blocked.json()["error"] == "The subject data key was not removed from the live store in this process."
    with psycopg.connect(url) as conn:
        login = conn.execute("SELECT email FROM gab_logins WHERE principal_id = 'prn_owner'").fetchone()
        agent = conn.execute(
            "SELECT status FROM gab_agents WHERE agent_id = 'shopper-01' AND principal_id = 'prn_owner'"
        ).fetchone()
        session = conn.execute(
            "SELECT count(*) FROM gab_sessions WHERE kind = 'portal' AND subject_id = 'prn_owner'"
        ).fetchone()
        audits = conn.execute("SELECT count(*) FROM gab_audit WHERE path = '/v1/portal/subject'").fetchone()
    assert login is not None
    assert agent[0] == "active"
    assert session[0] == 1
    assert audits[0] == 0
    still = app.get("/v1/portal/agents", headers=_auth(token))
    assert still.status_code == 200, still.text
    bureau = app.app.state.bureau
    bureau.key_provider = EnvKeyProvider({}, master_key=b"\x11" * 32, subject_key=b"\x22" * 32)
    bureau.dek_store = InProcessDekStore(b"\x22" * 32)
    removed = _delete_subject(app, token, soft)
    assert removed.status_code == 200, removed.text
    with psycopg.connect(url) as conn:
        login = conn.execute("SELECT email FROM gab_logins WHERE principal_id = 'prn_owner'").fetchone()
    assert login is None


def test_another_principals_dek_row_does_not_block_removal():
    app, url, token, soft, _operator_id, _merchant_id = _postgres_portal()
    bureau = app.app.state.bureau
    provider = EnvKeyProvider({}, master_key=b"\x11" * 32, subject_key=b"\x22" * 32)
    bureau.key_provider = provider
    bureau.dek_store = None
    bureau.master_key_configured = False
    owner_ref = provider.subject_ref("prn_owner")
    other_ref = provider.subject_ref("prn_other")
    assert owner_ref != other_ref
    with psycopg.connect(url) as conn:
        conn.execute(
            """
            INSERT INTO gab_subject_deks (subject_ref, wrapped_dek, created_at)
            VALUES (%s, 'b3duZXI=', '2026-10-18T00:00:00Z'),
                   (%s, 'b3RoZXI=', '2026-10-18T00:00:00Z')
            """,
            (owner_ref, other_ref),
        )
    blocked = _delete_subject(app, token, soft)
    assert blocked.status_code == 503
    assert blocked.json()["error"] == "The subject data key was not removed from the live store in this process."
    still = app.get("/v1/portal/agents", headers=_auth(token))
    assert still.status_code == 200, still.text
    with psycopg.connect(url) as conn:
        conn.execute("DELETE FROM gab_subject_deks WHERE subject_ref = %s", (owner_ref,))
        left = conn.execute(
            "SELECT subject_ref FROM gab_subject_deks WHERE subject_ref = %s",
            (other_ref,),
        ).fetchone()
    assert left is not None
    removed = _delete_subject(app, token, soft)
    assert removed.status_code == 200, removed.text
    with psycopg.connect(url) as conn:
        login = conn.execute("SELECT email FROM gab_logins WHERE principal_id = 'prn_owner'").fetchone()
        other = conn.execute(
            "SELECT subject_ref FROM gab_subject_deks WHERE subject_ref = %s",
            (other_ref,),
        ).fetchone()
    assert login is None
    assert other is not None


def test_a_short_subject_ref_key_is_an_explicit_error(caplog):
    raw = _b64(b"SYNTHETICBADKEYVALUE")
    with caplog.at_level("ERROR", logger="kata_service.settings"):
        settings = settings_from_env(
            {
                "GAB_ENV": "sandbox",
                "GAB_MASTER_KEY": _b64(b"\x11" * 32),
                "GAB_SUBJECT_REF_KEY": raw,
            }
        )
    assert settings.key_provider is None
    assert settings.master_key_configured is True
    assert settings.config_error == "GAB_SUBJECT_REF_KEY must decode to 32 bytes"
    assert any(record.message == "GAB_SUBJECT_REF_KEY is not a usable subject ref key" for record in caplog.records)
    assert raw not in (settings.config_error or "")
    assert all(raw not in record.message for record in caplog.records)


def test_an_invalid_base64_subject_ref_key_is_an_explicit_error(caplog):
    raw = "not-a-key"
    with caplog.at_level("ERROR", logger="kata_service.settings"):
        settings = settings_from_env({"GAB_ENV": "sandbox", "GAB_SUBJECT_REF_KEY": raw})
    assert settings.key_provider is None
    assert settings.master_key_configured is False
    assert settings.config_error == "GAB_SUBJECT_REF_KEY is not valid base64"
    assert any(record.message == "GAB_SUBJECT_REF_KEY is not a usable subject ref key" for record in caplog.records)
    assert raw not in (settings.config_error or "")
    assert all(raw not in record.message for record in caplog.records)
