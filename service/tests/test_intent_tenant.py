# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""GET /v1/agents/{id}/intents is limited to the operator that owns the agent.

A different tenant receives the same 404 body as a missing agent. SYNTHETIC TEST DATA.
"""

from __future__ import annotations

from tests.test_bureau import _agreement, _auth, _client, _key, _org, _register
from tests.test_postgres_path import _database_url, _reset


def _assert_intents(client) -> None:
    operator = _org(client, "SYNTHETIC TEST DATA", "agent_operator")
    other = _org(client, "SYNTHETIC TEST DATA other", "merchant")
    operator_key = _key(client, operator["org_id"])
    other_key = _key(client, other["org_id"])
    _register(client, operator_key)
    stored = client.post(
        "/v1/agents/shopper-01/intents",
        headers={**_auth(operator_key), "Content-Type": "application/json"},
        content=_agreement().to_json(),
    )
    assert stored.status_code == 200, stored.text

    missing = client.get("/v1/agents/missing-agent/intents", headers=_auth(operator_key))
    hidden = client.get("/v1/agents/shopper-01/intents", headers=_auth(other_key))
    owned = client.get("/v1/agents/shopper-01/intents", headers=_auth(operator_key))

    assert missing.status_code == 404
    assert hidden.status_code == 404
    assert hidden.json() == missing.json()
    assert hidden.json() == {"error": "agent was not found"}
    assert owned.status_code == 200
    assert owned.json()[0]["agreement_id"] == "agr_test"


def test_other_tenant_intents_match_a_missing_agent():
    _assert_intents(_client())


def test_other_tenant_intents_match_a_missing_agent_on_postgres():
    url = _database_url()
    _reset(url)
    _assert_intents(_client(database_url=url, schema_url=url))
