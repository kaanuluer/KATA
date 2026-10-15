# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Cheap verifies should not carry a report."""

from __future__ import annotations

from kata_service.defenses import ScoreContext, ScorePolicy, link_strength

from test_bureau import _action, _agreement, _auth, _client, _key, _org, _register


def test_link_strength_drops_a_cheap_verify_and_keeps_a_real_one():
    policy = ScorePolicy()
    report = {"reporter_org_id": "org-merchant", "action_id": "act_1"}
    cheap = ScoreContext(
        now="2026-10-15T00:00:00Z",
        interactions=[{"counterparty_org_id": "org-merchant", "action_id": "act_1", "amount": "2", "at": "2026-10-15T00:00:00Z"}],
    )
    real = ScoreContext(
        now="2026-10-15T00:00:00Z",
        interactions=[{"counterparty_org_id": "org-merchant", "action_id": "act_1", "amount": "1300", "at": "2026-10-04T00:00:00Z"}],
    )
    assert link_strength(report, policy, cheap) == 0
    assert link_strength(report, policy, real) == 1


def test_a_two_dollar_verify_does_not_let_a_chargeback_count():
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
    allowed = client.post(
        "/v1/verify",
        headers=_auth(merchant_key),
        json={"agent_id": "shopper-01", "action": _action(2, "act_cheap")},
    )
    assert allowed.json()["verdict"] == "ALLOW"
    before = client.get("/v1/agents/shopper-01", headers=_auth(operator_key)).json()["score"]
    filed = client.post(
        "/v1/reports",
        headers=_auth(merchant_key),
        json={
            "agent_id": "shopper-01",
            "kind": "chargeback",
            "evidence_hash": "sha256:" + "ab" * 32,
            "summary": "Cheap link",
            "action_id": "act_cheap",
        },
    )
    assert filed.status_code == 200, filed.text
    assert filed.json()["counts"] is False
    after = client.get("/v1/agents/shopper-01", headers=_auth(operator_key)).json()["score"]
    assert after == before
