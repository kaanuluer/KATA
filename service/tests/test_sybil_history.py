# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Re-registration links survive a new operator and the 14-day window."""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

from kata_intent import private_key_from_seed

from kata_service.defenses import ScorePolicy, confirmed_malicious, decay_factor, lookback_days

from test_bureau import AT, _action, _agreement, _auth, _client, _key, _org, _register


def test_lookback_is_longer_for_a_revoked_agent_and_for_a_signal():
    policy = ScorePolicy()
    active = {"status": "active", "score": 400}
    revoked = {"status": "revoked", "score": 700}
    assert lookback_days(active, policy, signal=False) == 14
    assert lookback_days(active, policy, signal=True) == 90
    assert lookback_days(revoked, policy, signal=False) == 180
    assert confirmed_malicious({"status": "active"}, [{"kind": "fraud_incident", "excluded": False}])
    assert decay_factor("2026-09-15T00:00:00Z", "2026-10-15T00:00:00Z", 30) == 0.5


def test_a_new_operator_inherits_fraud_after_the_short_window():
    client = _client()
    operator = _org(client, "Harbor Agents", "agent_operator")
    other = _org(client, "Other Agents", "agent_operator")
    bank = _org(client, "Harbor Bank", "bank_issuer")
    operator_key = _key(client, operator["org_id"])
    other_key = _key(client, other["org_id"])
    bank_key = _key(client, bank["org_id"])
    service = client.app.state.bureau
    service.repo.set_org_created_at(bank["org_id"], "2020-01-01T00:00:00Z")
    _register(client, operator_key)
    client.post(
        "/v1/agents/shopper-01/intents",
        headers={**_auth(operator_key), "Content-Type": "application/json"},
        content=_agreement().to_json(),
    )
    assert (
        client.post(
            "/v1/verify",
            headers=_auth(bank_key),
            json={"agent_id": "shopper-01", "action": _action(100, "act_fraud")},
        ).json()["verdict"]
        == "ALLOW"
    )
    filed = client.post(
        "/v1/reports",
        headers=_auth(bank_key),
        json={
            "agent_id": "shopper-01",
            "kind": "fraud_incident",
            "evidence_hash": "sha256:" + "ab" * 32,
            "summary": "Synthetic fraud",
            "action_id": "act_fraud",
        },
    )
    assert filed.status_code == 200, filed.text
    assert client.post("/v1/agents/shopper-01/status", headers=_auth(operator_key), json={"status": "revoked"}).status_code == 200
    denied = service.repo.get_agent("shopper-01")
    denied["updated_at"] = _days_ago(20)
    service.repo.save_agent(denied)
    service.repo.add_signal({"agent_id": "shopper-01", "kind": "device", "value": "desk-east", "created_at": denied["updated_at"]})
    fresh = private_key_from_seed(hashlib.sha256(b"shopper-sybil").digest())
    created = client.post(
        "/v1/agents",
        headers=_auth(other_key),
        json={
            "agent_id": "shopper-02",
            "principal_id": "prn_sybil",
            "public_key": fresh.public.to_jwk(),
            "verification_level": "operator_verified",
            "proofing_evidence": "sha256:" + "ee" * 32,
            "device_signal": "desk-east",
        },
    )
    assert created.status_code == 200, created.text
    body = created.json()
    assert body["identity_link"]["linked_agent_ids"] == ["shopper-01"]
    assert body["identity_link"]["penalty"] == 0
    inherited = [item for item in body["score_reasons"] if item["code"] == "INHERITED_HISTORY"]
    assert inherited
    assert inherited[0]["points"] == -120
    assert body["score"] == 580
    service.repo.identity_links[0]["created_at"] = _days_ago(30)
    agent = service.repo.get_agent("shopper-02")
    service._rescore(agent)
    service.repo.save_agent(agent)
    decayed = client.get("/v1/agents/shopper-02", headers=_auth(other_key)).json()
    points = [item["points"] for item in decayed["score_reasons"] if item["code"] == "INHERITED_HISTORY"]
    assert points == [-60]
    assert decayed["score"] == 640


def test_payment_instrument_links_a_fresh_operator():
    client = _client()
    operator = _org(client, "Harbor Agents", "agent_operator")
    other = _org(client, "Other Agents", "agent_operator")
    operator_key = _key(client, operator["org_id"])
    other_key = _key(client, other["org_id"])
    _register(client, operator_key)
    assert client.post("/v1/agents/shopper-01/status", headers=_auth(operator_key), json={"status": "revoked"}).status_code == 200
    service = client.app.state.bureau
    denied = service.repo.get_agent("shopper-01")
    denied["updated_at"] = _days_ago(40)
    service.repo.save_agent(denied)
    service.repo.add_signal(
        {"agent_id": "shopper-01", "kind": "payment", "value": "instrument-hash", "created_at": denied["updated_at"]}
    )
    fresh = private_key_from_seed(hashlib.sha256(b"shopper-pay").digest())
    created = client.post(
        "/v1/agents",
        headers=_auth(other_key),
        json={
            "agent_id": "shopper-02",
            "principal_id": "prn_pay",
            "public_key": fresh.public.to_jwk(),
            "verification_level": "operator_verified",
            "proofing_evidence": "sha256:" + "ef" * 32,
            "payment_instrument": "instrument-hash",
        },
    )
    assert created.status_code == 200, created.text
    assert created.json()["identity_link"]["linked_agent_ids"] == ["shopper-01"]


def _days_ago(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
