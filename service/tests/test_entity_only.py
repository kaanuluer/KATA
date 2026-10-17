# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Entity-only mode. SYNTHETIC TEST DATA only. Flags default off."""

from __future__ import annotations

import os
from urllib.parse import urlparse

import pytest

from kata_service.bureau import BureauError
from kata_service.entity_mode import downgrade_network_deny, screen_request
from kata_service.settings import settings_from_env

from test_bureau import _action, _agreement, _auth, _client, _key


def test_flags_default_off():
    settings = settings_from_env({})
    assert settings.entity_only is False
    assert settings.network_step_up is False


def test_free_text_and_unknown_fields_are_rejected_only_when_the_flag_is_on():
    screen_request("verify", {"agent_id": "shopper-01", "action": {"note": "settled on 2026-10-17"}})
    with pytest.raises(BureauError, match="unknown field"):
        screen_request("verify", {"agent_id": "shopper-01", "action": _action(10), "email": "synthetic-test-data@example.com"})
    with pytest.raises(BureauError, match="email or phone"):
        screen_request("report", {"summary": "reach synthetic-test-data@example.com"})
    with pytest.raises(BureauError, match="email or phone"):
        screen_request("dispute", {"statement": "phone +14155550100"})
    client = _ready(entity_only=True)
    operator_key = client.operator_key
    unknown = client.post(
        "/v1/verify",
        headers=_auth(operator_key),
        json={"agent_id": "shopper-01", "action": _action(10), "ssn": "synthetic"},
    )
    assert unknown.status_code == 400
    assert unknown.json()["error"] == "unknown field"
    mailed = client.post(
        "/v1/reports",
        headers=_auth(client.merchant_key),
        json={
            "agent_id": "shopper-01",
            "kind": "fraud_incident",
            "evidence_hash": "a" * 64,
            "summary": "buyer synthetic-test-data@example.com",
        },
    )
    assert mailed.status_code == 400
    assert "email or phone" in mailed.json()["error"]
    open_mode = _ready()
    ignored = open_mode.post(
        "/v1/verify",
        headers=_auth(open_mode.operator_key),
        json={"agent_id": "shopper-01", "action": _action(10), "ssn": "synthetic"},
    )
    assert ignored.status_code == 200, ignored.text
    assert ignored.json()["verdict"] == "ALLOW"
    assert "principal_id" not in ignored.json()


def test_entity_kind_is_required_and_email_lookup_is_rejected():
    client = _client(entity_only=True)
    missing = client.post(
        "/v1/orgs",
        headers=_auth("admin-test-token"),
        json={"name": "Synthetic Operator", "org_type": "agent_operator"},
    )
    assert missing.status_code == 400
    created = client.post(
        "/v1/orgs",
        headers=_auth("admin-test-token"),
        json={"name": "Synthetic Operator", "org_type": "agent_operator", "entity_kind": "business"},
    )
    assert created.status_code == 200, created.text
    assert created.json()["entity_kind"] == "business"
    operator_key = _key(client, created.json()["org_id"])
    refused = client.post(
        "/v1/agents",
        headers=_auth(operator_key),
        json={**_body(), "principal_email": "synthetic-test-data@example.com", "entity_kind": "personal"},
    )
    assert refused.status_code == 400
    assert refused.json()["error"] == "personal email is not accepted"
    accepted = client.post(
        "/v1/agents",
        headers=_auth(operator_key),
        json={**_body(), "entity_kind": "personal"},
    )
    assert accepted.status_code == 200, accepted.text
    assert accepted.json()["entity_kind"] == "personal"
    assert "principal_id" in accepted.json()


def test_network_signal_deny_can_step_up_and_velocity_cannot():
    stepped = downgrade_network_deny(
        {"verdict": "DENY", "kata_decision": "BLOCK", "reasons": ["DEVICE_SIGNAL"]}
    )
    assert stepped["verdict"] == "STEP_UP"
    assert stepped["kata_decision"] == "STEP_UP"
    assert "NETWORK_SIGNAL_STEP_UP" in stepped["reasons"]
    held = downgrade_network_deny({"verdict": "DENY", "kata_decision": "BLOCK", "reasons": ["VELOCITY_COUNT"]})
    assert held["verdict"] == "DENY"
    client = _ready(network_step_up=True)
    denied = client.post(
        "/v1/verify",
        headers=_auth(client.operator_key),
        json={"agent_id": "shopper-01", "action": _action(4200, "act_over")},
    )
    assert denied.status_code == 200, denied.text
    assert denied.json()["verdict"] == "DENY"


def test_public_pages_do_not_offer_those_use_cases():
    client = _client()
    for path in ("/", "/docs/quickstart"):
        text = client.get(path).text.lower()
        for phrase in ("credit score", "insurance", "employment", "compliant", "certified"):
            assert phrase not in text


def test_postgres_entity_kind_column():
    url = os.environ.get("GAB_TEST_DATABASE_URL")
    if not url:
        if os.environ.get("GITHUB_ACTIONS"):
            pytest.fail("GAB_TEST_DATABASE_URL is required in CI")
        pytest.skip("GAB_TEST_DATABASE_URL is not set")
    if urlparse(url).hostname not in {"localhost", "127.0.0.1"}:
        pytest.fail("GAB_TEST_DATABASE_URL must point at localhost")
    import psycopg

    from kata_service.bureau_pg import PostgresRepo

    with psycopg.connect(url, autocommit=True) as conn:
        conn.execute("DROP SCHEMA IF EXISTS public CASCADE")
        conn.execute("DROP SCHEMA IF EXISTS gab_sandbox CASCADE")
        conn.execute("CREATE SCHEMA public")
        conn.execute("GRANT ALL ON SCHEMA public TO public")
    PostgresRepo(url, url).migration_versions()
    with psycopg.connect(url) as conn:
        rows = conn.execute(
            """
            SELECT table_name FROM information_schema.columns
            WHERE column_name = 'entity_kind' AND table_name IN ('gab_agents', 'gab_organizations')
            """
        ).fetchall()
    assert {row[0] for row in rows} == {"gab_agents", "gab_organizations"}


def _ready(**overrides):
    client = _client(**overrides)
    kind = {"entity_kind": "business"} if overrides.get("entity_only") else {}
    operator = client.post(
        "/v1/orgs",
        headers=_auth("admin-test-token"),
        json={"name": "Synthetic Operator", "org_type": "agent_operator", **kind},
    )
    assert operator.status_code == 200, operator.text
    merchant = client.post(
        "/v1/orgs",
        headers=_auth("admin-test-token"),
        json={"name": "Synthetic Merchant", "org_type": "merchant", **kind},
    )
    assert merchant.status_code == 200, merchant.text
    operator_key = _key(client, operator.json()["org_id"])
    client.operator_key = operator_key
    client.merchant_key = _key(client, merchant.json()["org_id"])
    registered = client.post("/v1/agents", headers=_auth(operator_key), json=_register_body(kind.get("entity_kind")))
    assert registered.status_code == 200, registered.text
    agreement = _agreement()
    stored = client.post(
        f"/v1/agents/shopper-01/intents",
        headers={**_auth(operator_key), "Content-Type": "application/json"},
        content=agreement.to_json(),
    )
    assert stored.status_code == 200, stored.text
    return client


def _body() -> dict:
    return _register_body()


def _register_body(entity_kind: str | None = None, principal_id: str = "prn_person") -> dict:
    from test_bureau import _agent_keys

    _principal, agent = _agent_keys()
    body = {
        "agent_id": "shopper-01",
        "principal_id": principal_id,
        "public_key": agent.public.to_jwk(),
        "verification_level": "operator_verified",
    }
    if entity_kind:
        body["entity_kind"] = entity_kind
    return body
