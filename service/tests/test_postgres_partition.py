# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Live and test rows stay apart in Postgres.

The memory repository already filters on is_test. These cases run the same
API against PostgresRepo, which is what production uses.
"""

from __future__ import annotations

import hashlib

import psycopg
from kata_intent import Actor, Agreement, private_key_from_seed

from kata_service.bureau import reset_test_mode, use_test_mode

from tests.test_bureau import AT, EXPIRY, _action, _agent_keys, _agreement, _auth, _client, _key, _org
from tests.test_postgres_path import _database_url, _reset

EVIDENCE = "sha256:" + "ab" * 32
HOOK = "https://merchant.example/hooks/gab"


class _Quiet:
    def send(self, url, body):
        return None


def _test_key(client, org_id: str, name: str) -> str:
    issued = client.post(
        f"/v1/orgs/{org_id}/keys",
        headers=_auth("admin-test-token"),
        json={"name": name, "environment": "test"},
    )
    assert issued.status_code == 200, issued.text
    token = issued.json()["token"]
    assert token.startswith("gab_test_")
    return token


def _sandbox_agreement():
    principal = private_key_from_seed(hashlib.sha256(b"bureau-principal").digest())
    agent = private_key_from_seed(hashlib.sha256(b"bureau-agent-sandbox").digest())
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
    return agreement


def _store(client, key: str, agreement) -> None:
    stored = client.post(
        "/v1/agents/shopper-01/intents",
        headers={**_auth(key), "Content-Type": "application/json"},
        content=agreement.to_json(),
    )
    assert stored.status_code == 200, stored.text


def _agent(client, key: str) -> dict:
    response = client.get("/v1/agents/shopper-01", headers=_auth(key))
    assert response.status_code == 200, response.text
    return response.json()


def _report(client, key: str, action_id: str, *, shared_signal: str | None = None) -> None:
    body = {
        "agent_id": "shopper-01",
        "kind": "fraud_incident",
        "evidence_hash": EVIDENCE,
        "summary": "Disputed charge",
        "action_id": action_id,
    }
    if shared_signal:
        body["shared_signal"] = shared_signal
    filed = client.post("/v1/reports", headers=_auth(key), json=body)
    assert filed.status_code == 200, filed.text


def _settled(client, key: str, action_id: str, evidence: str, shared_signal: str) -> None:
    filed = client.post(
        "/v1/reports",
        headers=_auth(key),
        json={
            "agent_id": "shopper-01",
            "kind": "transaction_outcome",
            "outcome": "settled",
            "evidence_hash": evidence,
            "summary": "Settled purchase",
            "action_id": action_id,
            "shared_signal": shared_signal,
        },
    )
    assert filed.status_code == 200, filed.text


def _verify(client, key: str, action_id: str) -> None:
    allowed = client.post(
        "/v1/verify",
        headers=_auth(key),
        json={"agent_id": "shopper-01", "action": _action(100, action_id)},
    )
    assert allowed.status_code == 200, allowed.text
    assert allowed.json()["verdict"] == "ALLOW"


def test_postgres_keeps_live_and_test_rows_apart():
    url = _database_url()
    _reset(url)
    client = _client(database_url=url, schema_url=url)
    operator = _org(client, "Harbor Agents", "agent_operator")
    merchant = _org(client, "Techstore", "merchant")
    wallet = _org(client, "Northwind Wallet", "wallet")
    service = client.app.state.bureau
    service.sender = _Quiet()
    service.webhook_sleep = lambda _delay: None
    assert "007_partition.sql" in service.repo.migration_versions()

    live_operator = _key(client, operator["org_id"], "live")
    test_operator = _test_key(client, operator["org_id"], "sandbox")
    live_merchant = _key(client, merchant["org_id"], "merchant-live")
    test_merchant = _test_key(client, merchant["org_id"], "merchant-sandbox")
    test_wallet = _test_key(client, wallet["org_id"], "wallet-sandbox")

    _principal, live_key = _agent_keys()
    live_created = client.post(
        "/v1/agents",
        headers=_auth(live_operator),
        json={
            "agent_id": "shopper-01",
            "principal_id": "prn_person",
            "public_key": live_key.public.to_jwk(),
            "verification_level": "operator_verified",
            "device_signal": "shared-desk",
        },
    )
    assert live_created.status_code == 200, live_created.text
    live_agent = live_created.json()
    assert live_agent["environment"] == "live"
    hidden = client.get("/v1/agents/shopper-01", headers=_auth(test_operator))
    assert hidden.status_code == 404
    sandbox_key = private_key_from_seed(hashlib.sha256(b"bureau-agent-sandbox").digest())
    registered = client.post(
        "/v1/agents",
        headers=_auth(test_operator),
        json={
            "agent_id": "shopper-01",
            "principal_id": "prn_person",
            "public_key": sandbox_key.public.to_jwk(),
            "verification_level": "operator_verified",
            "device_signal": "shared-desk",
        },
    )
    assert registered.status_code == 200, registered.text
    assert registered.json()["environment"] == "test"
    assert registered.json()["fingerprint"] != live_agent["fingerprint"]
    assert _agent(client, test_operator)["environment"] == "test"
    again = client.post(
        "/v1/agents",
        headers=_auth(live_operator),
        json={
            "agent_id": "shopper-01",
            "principal_id": "prn_person",
            "public_key": sandbox_key.public.to_jwk(),
            "verification_level": "operator_verified",
        },
    )
    assert again.status_code == 409
    still_live = _agent(client, live_operator)
    assert still_live["environment"] == "live"
    assert still_live["fingerprint"] == live_agent["fingerprint"]
    assert still_live["score"] == live_agent["score"]

    _store(client, live_operator, _agreement())
    _store(client, test_operator, _sandbox_agreement())
    _verify(client, live_merchant, "act_live")
    _verify(client, test_merchant, "act_test")
    live_before = _agent(client, live_operator)["score"]
    test_before = _agent(client, test_operator)["score"]

    _report(client, test_merchant, "act_test")
    assert _agent(client, live_operator)["score"] == live_before
    assert _agent(client, test_operator)["score"] < test_before
    test_after_report = _agent(client, test_operator)["score"]
    live_reports = client.get("/v1/agents/shopper-01/reports", headers=_auth(live_merchant))
    test_reports = client.get("/v1/agents/shopper-01/reports", headers=_auth(test_merchant))
    assert live_reports.json()["counts"]["fraud_incident"] == 0
    assert test_reports.json()["counts"]["fraud_incident"] == 1

    _report(client, live_merchant, "act_live")
    assert _agent(client, live_operator)["score"] < live_before
    assert _agent(client, test_operator)["score"] == test_after_report
    assert client.get("/v1/agents/shopper-01/reports", headers=_auth(live_merchant)).json()["counts"]["fraud_incident"] == 1

    repo = service.repo
    for enabled, reports in ((False, 1), (True, 1)):
        token = use_test_mode(enabled)
        try:
            assert len(repo.all_reports()) == reports
            assert len(repo.all_interactions()) == 1
            assert len(repo.list_agents()) == 1
            assert repo.list_agents()[0]["is_test"] is enabled
            assert repo.org_signal_groups() == []
        finally:
            reset_test_mode(token)
    signal_rows = repo._all(
        "SELECT is_test FROM gab_org_signals WHERE value = %s ORDER BY is_test",
        ("shared-desk",),
    )
    assert signal_rows == [(False,), (True,)]

    live_score = _agent(client, live_operator)["score"]
    test_score = _agent(client, test_operator)["score"]
    test_assurance = _agent(client, test_operator)["assurance_level"]
    attested = client.post("/v1/agents/shopper-01/attest", headers=_auth(test_wallet))
    assert attested.status_code == 200, attested.text
    attested_body = attested.json()
    assert attested_body["environment"] == "test"
    assert attested_body["verification_level"] == "institution_attested"
    assert attested_body["assurance_level"] == test_assurance
    assert attested_body["score"] == test_score
    live_after_attest = _agent(client, live_operator)
    assert live_after_attest["environment"] == "live"
    assert live_after_attest["verification_level"] == "operator_verified"
    assert live_after_attest["score"] == live_score

    live_sub = client.post(
        "/v1/subscriptions",
        headers=_auth(live_merchant),
        json={"agent_id": "shopper-01", "webhook_url": HOOK},
    )
    assert live_sub.status_code == 200, live_sub.text
    test_sub = client.post(
        "/v1/subscriptions",
        headers=_auth(test_merchant),
        json={"agent_id": "shopper-01", "webhook_url": HOOK},
    )
    assert test_sub.status_code == 200, test_sub.text
    duplicate = client.post(
        "/v1/subscriptions",
        headers=_auth(live_merchant),
        json={"agent_id": "shopper-01", "webhook_url": HOOK},
    )
    assert duplicate.status_code == 409
    live_id = live_sub.json()["subscription_id"]
    test_id = test_sub.json()["subscription_id"]
    assert live_id != test_id

    with psycopg.connect(url) as conn:
        conn.execute(
            """
            INSERT INTO gab_subscriptions (subscription_id, org_id, agent_id, webhook_url, created_at)
            VALUES (%s, %s, %s, %s, %s)
            """,
            ("sub_legacy", merchant["org_id"], "shopper-01", "https://legacy.example/hooks/gab", "2026-01-01T00:00:00Z"),
        )
        legacy = conn.execute("SELECT is_test FROM gab_subscriptions WHERE subscription_id = %s", ("sub_legacy",)).fetchone()
    assert legacy == (False,)

    live_ids = {item["subscription_id"] for item in client.get("/v1/subscriptions", headers=_auth(live_merchant)).json()}
    test_ids = {item["subscription_id"] for item in client.get("/v1/subscriptions", headers=_auth(test_merchant)).json()}
    assert {live_id, "sub_legacy"} <= live_ids
    assert test_id in test_ids
    assert live_id not in test_ids
    assert test_id not in live_ids
    assert "sub_legacy" not in test_ids

    fired = client.post("/v1/webhooks/test", headers=_auth(live_merchant), json={"subscription_id": live_id})
    assert fired.status_code == 200, fired.text
    alert_id = fired.json()["alert_id"]
    refused = client.post("/v1/webhooks/test", headers=_auth(test_merchant), json={"subscription_id": live_id})
    assert refused.status_code == 404
    live_alerts = {item["alert_id"] for item in client.get("/v1/webhooks/deliveries", headers=_auth(live_merchant)).json()}
    test_alerts = {item["alert_id"] for item in client.get("/v1/webhooks/deliveries", headers=_auth(test_merchant)).json()}
    assert alert_id in live_alerts
    assert alert_id not in test_alerts


def test_postgres_ring_signals_do_not_cross_partitions():
    url = _database_url()
    _reset(url)
    client = _client(database_url=url, schema_url=url)
    operator = _org(client, "Harbor Agents", "agent_operator")
    merchant = _org(client, "Techstore", "merchant")
    client.app.state.bureau.sender = _Quiet()
    client.app.state.bureau.webhook_sleep = lambda _delay: None
    live_operator = _key(client, operator["org_id"], "live")
    test_operator = _test_key(client, operator["org_id"], "sandbox")
    live_merchant = _key(client, merchant["org_id"], "merchant-live")
    test_merchant = _test_key(client, merchant["org_id"], "merchant-sandbox")

    _principal, live_key = _agent_keys()
    live_created = client.post(
        "/v1/agents",
        headers=_auth(live_operator),
        json={
            "agent_id": "shopper-01",
            "principal_id": "prn_person",
            "public_key": live_key.public.to_jwk(),
            "verification_level": "operator_verified",
        },
    )
    assert live_created.status_code == 200, live_created.text
    sandbox_key = private_key_from_seed(hashlib.sha256(b"bureau-agent-sandbox").digest())
    registered = client.post(
        "/v1/agents",
        headers=_auth(test_operator),
        json={
            "agent_id": "shopper-01",
            "principal_id": "prn_person",
            "public_key": sandbox_key.public.to_jwk(),
            "verification_level": "operator_verified",
            "device_signal": "test-only-desk",
        },
    )
    assert registered.status_code == 200, registered.text
    _store(client, live_operator, _agreement())
    _store(client, test_operator, _sandbox_agreement())
    _verify(client, live_merchant, "act_live")
    _verify(client, test_merchant, "act_test")
    live_base = _agent(client, live_operator)["score"]
    test_base = _agent(client, test_operator)["score"]

    _settled(client, live_merchant, "act_live", "sha256:" + "cd" * 32, "test-only-desk")
    live_settled = _agent(client, live_operator)
    assert live_settled["score"] > live_base
    assert all(item["code"] != "RING_DISCOUNTED" for item in live_settled["score_reasons"])
    assert _agent(client, test_operator)["score"] == test_base

    _settled(client, test_merchant, "act_test", "sha256:" + "ef" * 32, "test-only-desk")
    test_settled = _agent(client, test_operator)
    assert test_settled["score"] == test_base
    assert any(item["code"] == "RING_DISCOUNTED" for item in test_settled["score_reasons"])
    assert _agent(client, live_operator)["score"] == live_settled["score"]

    repo = client.app.state.bureau.repo
    rows = repo._all("SELECT is_test FROM gab_org_signals WHERE value = %s ORDER BY is_test", ("test-only-desk",))
    assert rows == [(False,), (True,), (True,)]
    token = use_test_mode(False)
    try:
        assert repo.org_signal_groups() == []
    finally:
        reset_test_mode(token)
    token = use_test_mode(True)
    try:
        groups = repo.org_signal_groups()
        assert groups
        assert merchant["org_id"] in groups[0]
        assert operator["org_id"] in groups[0]
    finally:
        reset_test_mode(token)
