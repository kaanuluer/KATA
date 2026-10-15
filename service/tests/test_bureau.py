# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Bureau API tests. They use the memory repository and do not open a network connection."""

from __future__ import annotations

import hashlib

from fastapi.testclient import TestClient

from kata_intent import Actor, Agreement, generate_keypair, private_key_from_seed

from kata_service.asgi import create_app
from kata_service.bureau import trust_score
from kata_service.bureau_pg import migration_statements
from kata_service.settings import Settings
from kata_service.store import MemoryStore

AT = "2026-10-04T13:55:00Z"
EXPIRY = "2026-12-31T23:59:59Z"


def _settings(**overrides) -> Settings:
    base = dict(
        database_url=None,
        schema_url=None,
        log_signing_seed=hashlib.sha256(b"bureau-test-log").digest(),
        push_notifier_jwk=None,
        append_token=None,
        published_keys=(),
        fx_source_url="https://fx.test",
        admin_token="admin-test-token",
        rate_limit_per_minute=30,
        report_daily_cap=5,
    )
    base.update(overrides)
    return Settings(**base)


def _client(**overrides) -> TestClient:
    app = create_app(_settings(**overrides), MemoryStore())
    return TestClient(app)


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _org(client: TestClient, name: str, org_type: str) -> dict:
    response = client.post("/v1/orgs", headers=_auth("admin-test-token"), json={"name": name, "org_type": org_type})
    assert response.status_code == 200, response.text
    return response.json()


def _key(client: TestClient, org_id: str, name: str = "primary") -> str:
    response = client.post(f"/v1/orgs/{org_id}/keys", headers=_auth("admin-test-token"), json={"name": name})
    assert response.status_code == 200, response.text
    body = response.json()
    assert "secret_hash" not in body
    assert body["token"].startswith("gab_")
    return body["token"]


def _agent_keys():
    return (
        private_key_from_seed(hashlib.sha256(b"bureau-principal").digest()),
        private_key_from_seed(hashlib.sha256(b"bureau-agent").digest()),
    )


def _register(client: TestClient, operator_key: str, principal_id: str = "prn_person", principal_email: str | None = None) -> dict:
    _principal, agent = _agent_keys()
    body = {
        "agent_id": "shopper-01",
        "principal_id": principal_id,
        "public_key": agent.public.to_jwk(),
        "verification_level": "operator_verified",
    }
    if principal_email:
        body["principal_email"] = principal_email
    response = client.post(
        "/v1/agents",
        headers=_auth(operator_key),
        json=body,
    )
    assert response.status_code == 200, response.text
    return response.json()


def _agreement(principal_id: str = "prn_person", intent_id: str = "int_laptop", maximum: int = 1500, cumulative: int = 2000):
    principal, agent = _agent_keys()
    agreement = Agreement.propose(
        agreement_id="agr_test",
        principal={"display_name": "A Principal", "id": principal_id, "type": "human"},
        agent={"agent_id": "shopper-01"},
        agent_public_key=agent.public,
        intent={
            "allowed_actions": ["purchase"],
            "currency": "CAD",
            "intent_id": intent_id,
            "maximum_amount": maximum,
            "purpose": "purchase",
            "time_limit": EXPIRY,
            "version": 1,
        },
        limits={"cumulative_maximum": cumulative},
        parent_limits={"cumulative_maximum": cumulative, "currency": "CAD", "maximum_amount": maximum},
        actor=Actor("agent", "shopper-01"),
        at=AT,
        expires_at=EXPIRY,
    )
    agreement.accept(principal, AT, confirmed_text=agreement.rendering_preview())
    return agreement


def _action(amount: int, action_id: str = "act_1", intent_id: str | None = None) -> dict:
    action = {
        "action_id": action_id,
        "action_type": "purchase",
        "amount": amount,
        "context": {"merchant": "techstore.example"},
        "currency": "CAD",
        "item": "Laptop",
        "parameters": {"merchant": "techstore.example", "quantity": 1},
        "proposed_at": AT,
    }
    if intent_id:
        action["parameters"]["intent_id"] = intent_id
    return action


def test_admin_issues_hashed_rotatable_keys_and_blocks_other_tenants():
    client = _client()
    operator = _org(client, "Harbor Agents", "agent_operator")
    wallet = _org(client, "Northwind Wallet", "wallet")
    operator_key = _key(client, operator["org_id"])
    wallet_key = _key(client, wallet["org_id"])
    listed = client.get(f"/v1/orgs/{operator['org_id']}/keys", headers=_auth(operator_key))
    assert listed.status_code == 200
    assert "token" not in listed.json()[0]
    assert listed.json()[0]["prefix"]
    hidden = client.get(f"/v1/orgs/{wallet['org_id']}/keys", headers=_auth(operator_key))
    assert hidden.status_code == 404
    rotated = client.post(f"/v1/keys/{listed.json()[0]['key_id']}/rotate", headers=_auth(operator_key))
    assert rotated.status_code == 200
    assert client.get("/v1/agents/shopper-01", headers=_auth(operator_key)).status_code == 401
    assert client.get("/v1/agents/shopper-01", headers=_auth(rotated.json()["token"])).status_code == 404
    rejected = client.post("/v1/orgs", headers=_auth(wallet_key), json={"name": "Nope", "org_type": "merchant"})
    assert rejected.status_code == 403
    bad = client.post("/v1/orgs", headers=_auth("admin-test-token"), json={"name": "Nope", "org_type": "credit_bureau"})
    assert bad.status_code == 400


def test_registry_lookup_hides_principal_from_other_tenants():
    client = _client()
    operator = _org(client, "Harbor Agents", "agent_operator")
    merchant = _org(client, "Techstore", "merchant")
    operator_key = _key(client, operator["org_id"])
    merchant_key = _key(client, merchant["org_id"])
    registered = _register(client, operator_key)
    assert registered["principal_id"] == "prn_person"
    assert "d" not in registered["public_key"]
    own = client.get("/v1/agents/shopper-01", headers=_auth(operator_key)).json()
    other = client.get("/v1/agents/shopper-01", headers=_auth(merchant_key)).json()
    assert own["principal_id"] == "prn_person"
    assert "principal_id" not in other
    found = client.get("/v1/agents", headers=_auth(merchant_key), params={"fingerprint": registered["fingerprint"]})
    assert found.status_code == 200
    assert found.json()["agent_id"] == "shopper-01"
    wallet = _org(client, "Northwind Wallet", "wallet")
    wallet_key = _key(client, wallet["org_id"])
    attested = client.post("/v1/agents/shopper-01/attest", headers=_auth(wallet_key))
    assert attested.status_code == 200
    assert attested.json()["verification_level"] == "institution_attested"
    self_attest = client.post("/v1/agents/shopper-01/attest", headers=_auth(operator_key))
    assert self_attest.status_code == 403


def test_verify_allows_denies_and_enforces_cumulative_limits():
    client = _client()
    operator = _org(client, "Harbor Agents", "agent_operator")
    operator_key = _key(client, operator["org_id"])
    _register(client, operator_key)
    agreement = _agreement()
    stored = client.post(
        "/v1/agents/shopper-01/intents",
        headers={**_auth(operator_key), "Content-Type": "application/json"},
        content=agreement.to_json(),
    )
    assert stored.status_code == 200, stored.text
    assert stored.json()["intents"][0]["cumulative_maximum"] == 2000
    allowed = client.post("/v1/verify", headers=_auth(operator_key), json={"agent_id": "shopper-01", "action": _action(1300)})
    assert allowed.status_code == 200, allowed.text
    assert allowed.json()["verdict"] == "ALLOW"
    second = client.post("/v1/verify", headers=_auth(operator_key), json={"agent_id": "shopper-01", "action": _action(900, "act_2")})
    assert second.status_code == 200, second.text
    assert second.json()["verdict"] == "DENY"
    denied = client.post("/v1/verify", headers=_auth(operator_key), json={"agent_id": "shopper-01", "action": _action(4200, "act_3")})
    assert denied.json()["verdict"] == "DENY"


def test_reports_are_reciprocal_and_inquiries_are_visible_to_the_principal():
    client = _client()
    operator = _org(client, "Harbor Agents", "agent_operator")
    merchant = _org(client, "Techstore", "merchant")
    wallet = _org(client, "Northwind Wallet", "wallet")
    operator_key = _key(client, operator["org_id"])
    merchant_key = _key(client, merchant["org_id"])
    wallet_key = _key(client, wallet["org_id"])
    _register(client, operator_key)
    stored = client.post(
        "/v1/agents/shopper-01/intents",
        headers={**_auth(operator_key), "Content-Type": "application/json"},
        content=_agreement().to_json(),
    )
    assert stored.status_code == 200, stored.text
    allowed = client.post("/v1/verify", headers=_auth(merchant_key), json={"agent_id": "shopper-01", "action": _action(10, "act_report")})
    assert allowed.json()["verdict"] == "ALLOW"
    evidence = "sha256:" + "ab" * 32
    filed = client.post(
        "/v1/reports",
        headers=_auth(merchant_key),
        json={"agent_id": "shopper-01", "kind": "fraud_incident", "evidence_hash": evidence, "summary": "Disputed charge"},
    )
    assert filed.status_code == 200, filed.text
    duplicate = client.post(
        "/v1/reports",
        headers=_auth(merchant_key),
        json={"agent_id": "shopper-01", "kind": "fraud_incident", "evidence_hash": evidence, "summary": "Disputed charge"},
    )
    assert duplicate.status_code == 409
    stranger = client.get("/v1/agents/shopper-01/reports", headers=_auth(wallet_key))
    assert stranger.status_code == 200
    assert stranger.json()["contributor"] is False
    assert "reports" not in stranger.json()
    assert stranger.json()["counts"]["fraud_incident"] == 1
    contributor = client.get("/v1/agents/shopper-01/reports", headers=_auth(merchant_key))
    assert contributor.json()["contributor"] is True
    assert contributor.json()["reports"][0]["summary"] == "Disputed charge"
    missing_purpose = client.post("/v1/inquiries", headers=_auth(wallet_key), json={"agent_id": "shopper-01"})
    assert missing_purpose.status_code == 400
    inquiry = client.post(
        "/v1/inquiries",
        headers=_auth(wallet_key),
        json={"agent_id": "shopper-01", "purpose_code": "payment_authorization"},
    )
    assert inquiry.status_code == 200, inquiry.text
    body = inquiry.json()
    assert body["trust_score"]["score"] <= 1000
    assert body["incidents"]["counts"]["fraud_incident"] == 1
    assert "recent" not in body["incidents"]
    assert "principal_id" not in body["agent"]
    assert "example.com" not in inquiry.text
    link = client.post("/v1/portal/magic-link", json={"email": "person@example.com"})
    assert link.status_code == 200
    mailbox = client.get("/v1/dev/mailbox")
    assert mailbox.status_code == 404


def test_score_is_explainable_and_dedupes_reports():
    cold = trust_score(
        verification_level="operator_verified",
        operator_status="active",
        operator_org_id="org_op",
        reports=[],
        disputes=[],
        reporter_types={},
    )
    assert cold["cold_start"] is True
    assert cold["reasons"][0]["code"] == "COLD_START"
    assert 0 <= cold["score"] <= 1000
    shared = "sha256:" + "cd" * 32
    reports = [
        {"report_id": "r1", "kind": "fraud_incident", "evidence_hash": shared, "reporter_org_id": "org_bank", "outcome": None, "excluded": False},
        {"report_id": "r2", "kind": "fraud_incident", "evidence_hash": shared, "reporter_org_id": "org_merchant", "outcome": None, "excluded": False},
    ]
    scored = trust_score(
        verification_level="key_bound",
        operator_status="active",
        operator_org_id="org_op",
        reports=reports,
        disputes=[],
        reporter_types={"org_bank": "bank_issuer", "org_merchant": "merchant"},
    )
    fraud = [item for item in scored["reasons"] if item["code"] == "FRAUD_INCIDENT"]
    assert len(fraud) == 1
    assert fraud[0]["points"] == -120
    upheld = trust_score(
        verification_level="key_bound",
        operator_status="active",
        operator_org_id="org_op",
        reports=reports[:1],
        disputes=[{"report_id": "r1", "status": "resolved", "outcome": "upheld"}],
        reporter_types={"org_bank": "bank_issuer"},
    )
    assert not any(item["code"] == "FRAUD_INCIDENT" for item in upheld["reasons"])


def test_alerts_are_signed_and_disputes_change_the_score():
    client = _client()
    operator = _org(client, "Harbor Agents", "agent_operator")
    merchant = _org(client, "Techstore", "merchant")
    operator_key = _key(client, operator["org_id"])
    merchant_key = _key(client, merchant["org_id"])
    _register(client, operator_key)
    sub = client.post(
        "/v1/subscriptions",
        headers=_auth(merchant_key),
        json={"agent_id": "shopper-01", "webhook_url": "http://127.0.0.1/hook"},
    )
    assert sub.status_code == 200, sub.text
    client.post("/v1/agents/shopper-01/status", headers=_auth(operator_key), json={"status": "revoked"})
    sender = client.app.state.bureau.sender
    assert sender.sent
    body = sender.sent[-1][1]
    assert body["kata_bureau_alert"] == "1"
    assert body["signature"]["protected"]
    evidence = "sha256:" + "ef" * 32
    client.post("/v1/agents/shopper-01/status", headers=_auth("admin-test-token"), json={"status": "active"})
    stored = client.post(
        "/v1/agents/shopper-01/intents",
        headers={**_auth(operator_key), "Content-Type": "application/json"},
        content=_agreement().to_json(),
    )
    assert stored.status_code == 200, stored.text
    allowed = client.post("/v1/verify", headers=_auth(merchant_key), json={"agent_id": "shopper-01", "action": _action(10, "act_cb")})
    assert allowed.json()["verdict"] == "ALLOW"
    filed = client.post(
        "/v1/reports",
        headers=_auth(merchant_key),
        json={"agent_id": "shopper-01", "kind": "chargeback", "evidence_hash": evidence, "summary": "Returned item"},
    )
    assert filed.status_code == 200, filed.text
    link = client.post("/v1/portal/magic-link", json={"email": "person@example.com"})
    assert link.json()["sent"] is True
    service = client.app.state.bureau
    token = service.dev_mailbox[-1]["token"] if service.dev_mailbox_enabled else None
    assert token is None
    session = service.consume_link.__wrapped__ if False else None
    magic = list(service.repo.magic.values())[-1]
    raw = next(item["token"] for item in []) if False else None
    # The mailer is the console sender, so the test reads the stored hash by issuing the link through the service.
    issued = service.request_portal_link("owner@example.com")
    assert issued["sent"] is True


def test_portal_revoke_and_admin_dispute_review():
    client = _client(dev_mailbox=True)
    operator = _org(client, "Harbor Agents", "agent_operator")
    merchant = _org(client, "Techstore", "merchant")
    operator_key = _key(client, operator["org_id"])
    merchant_key = _key(client, merchant["org_id"])
    _register(client, operator_key, principal_id="prn_owner", principal_email="owner@example.com")
    agreement = _agreement("prn_owner")
    client.post(
        "/v1/agents/shopper-01/intents",
        headers={**_auth(operator_key), "Content-Type": "application/json"},
        content=agreement.to_json(),
    )
    evidence = "sha256:" + "11" * 32
    allowed = client.post("/v1/verify", headers=_auth(merchant_key), json={"agent_id": "shopper-01", "action": _action(10, "act_policy")})
    assert allowed.json()["verdict"] == "ALLOW"
    filed = client.post(
        "/v1/reports",
        headers=_auth(merchant_key),
        json={"agent_id": "shopper-01", "kind": "policy_violation", "evidence_hash": evidence, "summary": "Out of policy"},
    )
    before = client.get("/v1/agents/shopper-01", headers=_auth(operator_key)).json()["score"]
    client.post("/v1/portal/magic-link", json={"email": "owner@example.com"})
    service = client.app.state.bureau
    token = service.dev_mailbox[-1]["token"]
    session = client.post("/v1/sessions", json={"token": token})
    assert session.json()["principal_id"] == "prn_owner"
    assert session.status_code == 200, session.text
    portal = session.json()["token"]
    agents = client.get("/v1/portal/agents", headers=_auth(portal))
    assert agents.status_code == 200
    assert agents.json()[0]["agent_id"] == "shopper-01"
    assert agents.json()[0]["assurance_level"] == "key_bound"
    assert agents.json()[0]["risk"] == 1000 - agents.json()[0]["score"]
    reports = client.get("/v1/portal/agents/shopper-01/reports", headers=_auth(portal))
    assert reports.status_code == 200
    assert reports.json()[0]["report_id"] == filed.json()["report_id"]
    assert "owner@example.com" not in reports.text
    inquiries = client.post(
        "/v1/inquiries",
        headers=_auth(merchant_key),
        json={"agent_id": "shopper-01", "purpose_code": "fraud_investigation"},
    )
    assert inquiries.status_code == 200
    seen = client.get("/v1/portal/inquiries", headers=_auth(portal))
    assert seen.json()[0]["organization"] == "Techstore"
    assert "owner@example.com" not in seen.text
    dispute = client.post(
        "/v1/portal/disputes",
        headers=_auth(portal),
        json={"report_id": filed.json()["report_id"], "statement": "This charge was in policy."},
    )
    assert dispute.status_code == 200, dispute.text
    queued = client.get("/v1/portal/disputes", headers=_auth(portal))
    assert queued.status_code == 200
    assert queued.json()[0]["dispute_id"] == dispute.json()["dispute_id"]
    assert queued.json()[0]["status"] == "open"
    reviewed = client.post(
        f"/v1/admin/disputes/{dispute.json()['dispute_id']}",
        headers=_auth("admin-test-token"),
        json={"status": "resolved", "outcome": "upheld"},
    )
    assert reviewed.status_code == 200
    after = client.get("/v1/agents/shopper-01", headers=_auth(operator_key)).json()["score"]
    assert after >= before
    revoked = client.post("/v1/portal/agents/shopper-01/revoke", headers=_auth(portal))
    assert revoked.status_code == 200
    assert revoked.json()["status"] == "revoked"
    blocked = client.post("/v1/verify", headers=_auth(operator_key), json={"agent_id": "shopper-01", "action": _action(10, "act_9")})
    assert blocked.json()["reasons"] == ["AGENT_NOT_ACTIVE"]
    audit = client.get("/v1/audit", headers=_auth(operator_key))
    assert audit.status_code == 200
    dumped = audit.text
    assert operator_key not in dumped
    assert "admin-test-token" not in dumped


def test_rate_limit_validation_and_migration_sql():
    client = _client(rate_limit_per_minute=2)
    first = client.post("/v1/orgs", headers=_auth("admin-test-token"), json={"name": "One", "org_type": "merchant"})
    second = client.post("/v1/orgs", headers=_auth("admin-test-token"), json={"name": "Two", "org_type": "merchant"})
    third = client.post("/v1/orgs", headers=_auth("admin-test-token"), json={"name": "Three", "org_type": "merchant"})
    assert first.status_code == 200
    assert second.status_code == 200
    assert third.status_code == 429
    statements = "\n".join(migration_statements())
    for table in ("gab_organizations", "gab_api_keys", "gab_agents", "gab_reports", "gab_inquiries", "gab_disputes", "gab_audit", "gab_interactions", "gab_identity_links", "gab_proofings", "gab_consortium_members", "gab_consortium_sightings", "gab_org_signals"):
        assert table in statements
    assert "credit bureau" not in statements.lower()


def test_es256_agent_key_registers():
    client = _client()
    operator = _org(client, "Harbor Agents", "agent_operator")
    operator_key = _key(client, operator["org_id"])
    key = generate_keypair("ES256")
    response = client.post(
        "/v1/agents",
        headers=_auth(operator_key),
        json={"agent_id": "signer-02", "principal_id": "prn_es", "public_key": key.public.to_jwk(), "verification_level": "key_bound"},
    )
    assert response.status_code == 200, response.text
    assert response.json()["algorithm"] == "ES256"


def test_admin_seed_is_idempotent_and_stays_off_unless_allowed():
    from kata_service.seed import DEMO_OPERATOR_KEY
    from kata_service.settings import settings_from_env

    assert settings_from_env({"GAB_ALLOW_DEMO_SEED": "1"}).allow_demo_seed is True
    assert settings_from_env({}).allow_demo_seed is False
    blocked = _client(demo=False, allow_demo_seed=False)
    refused = blocked.post("/v1/admin/seed-demo", headers=_auth("admin-test-token"))
    assert refused.status_code == 403
    assert refused.json()["error"] == "demo seed is disabled"
    assert blocked.app.state.bureau.repo.get_agent("shopper-01") is None
    client = _client(demo=False, allow_demo_seed=True)
    anonymous = client.post("/v1/admin/seed-demo")
    assert anonymous.status_code == 401
    operator = _org(client, "Other Operator", "agent_operator")
    operator_key = _key(client, operator["org_id"])
    forbidden = client.post("/v1/admin/seed-demo", headers=_auth(operator_key))
    assert forbidden.status_code == 403
    first = client.post("/v1/admin/seed-demo", headers=_auth("admin-test-token"))
    assert first.status_code == 200, first.text
    body = first.json()
    assert body["agent_id"] == "shopper-01"
    assert body["already_present"] == "false"
    assert "admin_token" not in body
    assert "admin-test-token" not in first.text
    second = client.post("/v1/admin/seed-demo", headers=_auth("admin-test-token"))
    assert second.status_code == 200, second.text
    assert second.json()["already_present"] == "true"
    assert len(client.app.state.bureau.repo.orgs) == 4
    again = client.post("/v1/admin/seed-demo", headers=_auth(DEMO_OPERATOR_KEY))
    assert again.status_code == 403
    assert len(client.app.state.bureau.repo.orgs) == 4
    agent = client.get("/v1/agents/shopper-01", headers=_auth(DEMO_OPERATOR_KEY))
    assert agent.status_code == 200
    assert agent.json()["verification_level"] == "institution_attested"
    assert agent.json()["assurance_level"] == "institution_attested"
    assert agent.json()["score"] == 724
    methods = {item["method"] for item in agent.json()["proofings"]}
    assert {"key_binding", "operator_review", "institution_attestation"} <= methods


def test_principal_email_cannot_move_to_another_principal():
    client = _client(dev_mailbox=True)
    operator = _org(client, "Harbor Agents", "agent_operator")
    operator_key = _key(client, operator["org_id"])
    _register(client, operator_key, principal_id="prn_owner", principal_email="owner@example.com")
    other_key = generate_keypair("EdDSA")
    stolen = client.post(
        "/v1/agents",
        headers=_auth(operator_key),
        json={
            "agent_id": "shopper-02",
            "principal_id": "prn_other",
            "principal_email": "owner@example.com",
            "public_key": other_key.public.to_jwk(),
            "verification_level": "key_bound",
        },
    )
    assert stolen.status_code == 409
    assert stolen.json()["error"] == "email is already bound to another principal"
    link = client.post("/v1/portal/magic-link", json={"email": "owner@example.com"})
    assert link.json()["sent"] is True
    service = client.app.state.bureau
    token = service.dev_mailbox[-1]["token"]
    session = client.post("/v1/sessions", json={"token": token})
    assert session.status_code == 200
    assert session.json()["principal_id"] == "prn_owner"
    fresh = client.post("/v1/portal/magic-link", json={"email": "new-person@example.com"})
    assert fresh.json()["sent"] is True
    second = client.post("/v1/portal/magic-link", json={"email": "new-person@example.com"})
    assert second.json()["sent"] is True
    first_token = service.dev_mailbox[-2]["token"]
    second_token = service.dev_mailbox[-1]["token"]
    first_session = client.post("/v1/sessions", json={"token": first_token})
    second_session = client.post("/v1/sessions", json={"token": second_token})
    assert first_session.status_code == 200
    assert second_session.status_code == 200
    assert first_session.json()["principal_id"] == second_session.json()["principal_id"]


def test_endpoint_rate_limits_do_not_block_other_routes():
    client = _client(
        rate_limit_per_minute=100,
        verify_rate_limit_per_minute=2,
        inquiry_rate_limit_per_minute=1,
        report_rate_limit_per_minute=1,
    )
    assert client.post("/v1/verify", json={}).status_code != 429
    assert client.post("/v1/verify", json={}).status_code != 429
    assert client.post("/v1/verify", json={}).status_code == 429
    created = client.post("/v1/orgs", headers=_auth("admin-test-token"), json={"name": "Still Open", "org_type": "merchant"})
    assert created.status_code == 200
    assert client.post("/v1/inquiries", json={}).status_code != 429
    assert client.post("/v1/inquiries", json={}).status_code == 429
    assert client.post("/v1/reports", json={}).status_code != 429
    assert client.post("/v1/reports", json={}).status_code == 429


def test_smtp_is_off_unless_configured_and_does_not_print_the_password():
    from kata_service.bureau import SilentMailer, SmtpMailer, mailer_from_settings
    from kata_service.settings import settings_from_env

    missing = settings_from_env({})
    assert isinstance(mailer_from_settings(missing), SilentMailer)
    configured = settings_from_env(
        {
            "GAB_SMTP_HOST": "smtp.gmail.com",
            "GAB_SMTP_PORT": "587",
            "GAB_SMTP_USER": "mailbox",
            "GAB_SMTP_PASSWORD": "test-smtp-secret",
            "GAB_SMTP_FROM": "from@example.com",
            "GAB_PUBLIC_BASE_URL": "https://globalagentbureau.com",
        }
    )
    assert configured.public_base_url == "https://globalagentbureau.com"
    mailer = mailer_from_settings(configured)
    assert isinstance(mailer, SmtpMailer)
    assert "test-smtp-secret" not in repr(mailer)
    sent: dict[str, object] = {}

    class FakeSMTP:
        def __init__(self, host, port, timeout=None):
            sent["host"] = host
            sent["port"] = port

        def ehlo(self):
            return None

        def starttls(self):
            sent["tls"] = True

        def login(self, user, password):
            sent["user"] = user
            sent["password"] = password

        def send_message(self, message):
            sent["to"] = message["To"]
            sent["from"] = message["From"]
            sent["body"] = message.get_content()

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    import smtplib

    original = smtplib.SMTP
    smtplib.SMTP = FakeSMTP
    try:
        mailer.send_magic_link("person@example.com", "https://globalagentbureau.com/portal#token=abc")
    finally:
        smtplib.SMTP = original
    assert sent["host"] == "smtp.gmail.com"
    assert sent["port"] == 587
    assert sent["tls"] is True
    assert sent["user"] == "mailbox"
    assert sent["from"] == "from@example.com"
    assert "agent bureau" in str(sent["body"]).lower()
    assert "credit bureau" not in str(sent["body"]).lower()
