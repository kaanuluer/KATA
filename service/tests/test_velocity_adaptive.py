# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Segment, burst, and cash-out velocity checks."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from test_bureau import AT, _action, _agreement, _auth, _client, _key, _org, _register


def test_a_shopping_amount_uses_the_tighter_segment_window():
    client, key = _ready()
    action = _action(1200, "act_shop")
    action["segment"] = "shopping"
    result = client.post("/v1/verify", headers=_auth(key), json={"agent_id": "shopper-01", "action": action})
    assert result.json()["verdict"] == "DENY"
    assert "VELOCITY_AMOUNT" in result.json()["reasons"]


def test_a_burst_above_the_agents_own_median_steps_up():
    client, key = _ready()
    service = client.app.state.bureau
    for offset, day in enumerate((3, 2, 1)):
        service.repo.add_interaction(_row(f"old-{offset}", _days_ago(day), "100"))
    result = client.post("/v1/verify", headers=_auth(key), json={"agent_id": "shopper-01", "action": _action(400, "act_burst")})
    assert result.json()["verdict"] == "DENY"
    assert "VELOCITY_BURST" in result.json()["reasons"]


def test_a_cash_out_after_a_quiet_week_steps_up():
    client, key = _ready()
    client.app.state.bureau.repo.add_interaction(_row("quiet", _days_ago(10), "20"))
    result = client.post("/v1/verify", headers=_auth(key), json={"agent_id": "shopper-01", "action": _action(600, "act_quiet")})
    assert result.json()["verdict"] == "DENY"
    assert "VELOCITY_CASHOUT" in result.json()["reasons"]


def test_a_cash_out_after_settled_credit_steps_up():
    client, key = _ready()
    merchant = _org(client, "Techstore", "merchant")
    merchant_key = _key(client, merchant["org_id"])
    client.app.state.bureau.repo.set_org_created_at(merchant["org_id"], "2020-01-01T00:00:00Z")
    allowed = client.post(
        "/v1/verify",
        headers=_auth(merchant_key),
        json={"agent_id": "shopper-01", "action": _action(10, "act_settle")},
    )
    assert allowed.json()["verdict"] == "ALLOW"
    filed = client.post(
        "/v1/reports",
        headers=_auth(merchant_key),
        json={
            "agent_id": "shopper-01",
            "kind": "transaction_outcome",
            "outcome": "settled",
            "evidence_hash": "sha256:" + "cd" * 32,
            "summary": "Settled",
            "action_id": "act_settle",
        },
    )
    assert filed.status_code == 200, filed.text
    result = client.post("/v1/verify", headers=_auth(key), json={"agent_id": "shopper-01", "action": _action(600, "act_cash")})
    assert result.json()["verdict"] == "DENY"
    assert "VELOCITY_CASHOUT" in result.json()["reasons"]


def _ready():
    client = _client()
    operator = _org(client, "Harbor Agents", "agent_operator")
    key = _key(client, operator["org_id"])
    _register(client, key)
    stored = client.post(
        "/v1/agents/shopper-01/intents",
        headers={**_auth(key), "Content-Type": "application/json"},
        content=_agreement().to_json(),
    )
    assert stored.status_code == 200, stored.text
    return client, key


def _row(interaction_id: str, at: str, amount: str) -> dict:
    return {
        "interaction_id": interaction_id,
        "agent_id": "shopper-01",
        "operator_org_id": "org-1",
        "counterparty_org_id": "org-merchant",
        "action_id": interaction_id,
        "amount": amount,
        "currency": "CAD",
        "agreement_id": "agr_1",
        "at": at,
    }


def _days_ago(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
