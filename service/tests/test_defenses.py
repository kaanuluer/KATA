# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Defenses around the trust score, plus the synthetic before/after."""

from __future__ import annotations

import hashlib

from kata_intent import Actor, Agreement, private_key_from_seed

from kata_service.defenses import ScorePolicy
from kata_service.synthetic_score import synthetic_case

from test_bureau import AT, EXPIRY, _action, _agreement, _auth, _client, _key, _org, _register


def test_synthetic_case_is_labeled_and_shows_the_gap():
    result = synthetic_case()
    assert result["label"] == "SIMULATED"
    assert result["disclaimer"] == "SIMULATED / synthetic test data, not real customers"
    assert result["legacy_settled_score"] > result["defended_unlinked_score"]
    assert result["legacy_chargeback_score"] < result["defended_chargeback_score"]
    assert result["legacy_ring_score"] > result["defended_ring_score"]
    assert ("org-partner", "org-operator") in result["ring_edges"]


def test_unlinked_report_is_rejected_and_does_not_move_the_score():
    client = _client()
    operator = _org(client, "Harbor Agents", "agent_operator")
    merchant = _org(client, "Techstore", "merchant")
    operator_key = _key(client, operator["org_id"])
    merchant_key = _key(client, merchant["org_id"])
    _register(client, operator_key)
    before = client.get("/v1/agents/shopper-01", headers=_auth(operator_key)).json()["score"]
    filed = client.post(
        "/v1/reports",
        headers=_auth(merchant_key),
        json={
            "agent_id": "shopper-01",
            "kind": "chargeback",
            "evidence_hash": "sha256:" + "22" * 32,
            "summary": "No recorded verify",
        },
    )
    assert filed.status_code == 400, filed.text
    assert "link minimum" in filed.json()["error"]
    after = client.get("/v1/agents/shopper-01", headers=_auth(operator_key)).json()["score"]
    assert after == before
    listed = client.get("/v1/agents/shopper-01/reports", headers=_auth(merchant_key))
    assert listed.json()["counts"]["chargeback"] == 0


def test_velocity_count_steps_up_without_recording_the_second_spend():
    client = _client(score_policy=ScorePolicy(velocity_daily_count=1))
    operator = _org(client, "Harbor Agents", "agent_operator")
    operator_key = _key(client, operator["org_id"])
    _register(client, operator_key)
    client.post(
        "/v1/agents/shopper-01/intents",
        headers={**_auth(operator_key), "Content-Type": "application/json"},
        content=_agreement().to_json(),
    )
    first = client.post("/v1/verify", headers=_auth(operator_key), json={"agent_id": "shopper-01", "action": _action(10)})
    assert first.status_code == 200, first.text
    assert first.json()["verdict"] == "ALLOW"
    second = client.post(
        "/v1/verify",
        headers=_auth(operator_key),
        json={"agent_id": "shopper-01", "action": _action(10, "act_velocity")},
    )
    assert second.status_code == 200, second.text
    assert second.json()["verdict"] == "DENY"
    assert "VELOCITY_COUNT" in second.json()["reasons"]


def test_re_registration_inherits_a_penalty_from_a_revoked_agent():
    client = _client()
    operator = _org(client, "Harbor Agents", "agent_operator")
    operator_key = _key(client, operator["org_id"])
    _register(client, operator_key)
    revoked = client.post("/v1/agents/shopper-01/status", headers=_auth(operator_key), json={"status": "revoked"})
    assert revoked.status_code == 200
    fresh = private_key_from_seed(hashlib.sha256(b"shopper-02").digest())
    created = client.post(
        "/v1/agents",
        headers=_auth(operator_key),
        json={
            "agent_id": "shopper-02",
            "principal_id": "prn_next",
            "public_key": fresh.public.to_jwk(),
            "verification_level": "operator_verified",
            "proofing_evidence": "sha256:" + "ee" * 32,
            "device_signal": "desk-east",
        },
    )
    assert created.status_code == 200, created.text
    body = created.json()
    assert body["identity_link"]["linked_agent_ids"] == ["shopper-01"]
    assert body["identity_link"]["penalty"] == 80
    assert body["assurance_level"] == "operator_verified"
    assert body["score"] == 620
    assert any(item["code"] == "IDENTITY_LINK" for item in body["score_reasons"])


def test_linked_chargeback_is_held_while_a_young_reporter_is_disputed():
    client = _client(dev_mailbox=True)
    operator = _org(client, "Harbor Agents", "agent_operator")
    merchant = _org(client, "Techstore", "merchant")
    operator_key = _key(client, operator["org_id"])
    merchant_key = _key(client, merchant["org_id"])
    _register(client, operator_key, principal_id="prn_owner", principal_email="owner@example.com")
    client.post(
        "/v1/agents/shopper-01/intents",
        headers={**_auth(operator_key), "Content-Type": "application/json"},
        content=_agreement("prn_owner").to_json(),
    )
    allowed = client.post(
        "/v1/verify",
        headers=_auth(merchant_key),
        json={"agent_id": "shopper-01", "action": _action(10, "act_linked")},
    )
    assert allowed.json()["verdict"] == "ALLOW"
    before = client.get("/v1/agents/shopper-01", headers=_auth(operator_key)).json()["score"]
    filed = client.post(
        "/v1/reports",
        headers=_auth(merchant_key),
        json={
            "agent_id": "shopper-01",
            "kind": "chargeback",
            "evidence_hash": "sha256:" + "33" * 32,
            "summary": "Linked dispute",
            "action_id": "act_linked",
        },
    )
    assert filed.status_code == 200, filed.text
    assert filed.json()["counts"] is True
    dropped = client.get("/v1/agents/shopper-01", headers=_auth(operator_key)).json()["score"]
    assert dropped < before
    service = client.app.state.bureau
    client.post("/v1/portal/magic-link", json={"email": "owner@example.com"})
    token = service.dev_mailbox[-1]["token"]
    portal = client.post("/v1/sessions", json={"token": token}).json()["token"]
    from soft_passkey import assertion_for, bind_device

    soft = bind_device(client, portal)
    dispute = client.post(
        "/v1/portal/disputes",
        headers=_auth(portal),
        json={
            "report_id": filed.json()["report_id"],
            "statement": "The verify was legitimate.",
            "assertion": assertion_for(client, portal, soft),
        },
    )
    assert dispute.status_code == 200, dispute.text
    held = client.get("/v1/agents/shopper-01", headers=_auth(operator_key)).json()
    assert held["score"] >= before
    assert any(item["code"] == "DISPUTE_HOLD" for item in held["score_reasons"])
    rejected = client.post(
        f"/v1/admin/disputes/{dispute.json()['dispute_id']}",
        headers=_auth("admin-test-token"),
        json={"status": "resolved", "outcome": "rejected"},
    )
    assert rejected.status_code == 200
    restored = client.get("/v1/agents/shopper-01", headers=_auth(operator_key)).json()["score"]
    assert restored < before


def test_reciprocal_settled_reports_do_not_raise_the_score():
    client = _client()
    left = _org(client, "Left Operators", "agent_operator")
    right = _org(client, "Right Operators", "agent_operator")
    left_key = _key(client, left["org_id"])
    right_key = _key(client, right["org_id"])
    client.app.state.bureau.repo.set_org_created_at(left["org_id"], "2020-01-01T00:00:00Z")
    client.app.state.bureau.repo.set_org_created_at(right["org_id"], "2020-01-01T00:00:00Z")
    _register_named(client, left_key, "agent-left", "prn_left", b"left-agent")
    _register_named(client, right_key, "agent-right", "prn_right", b"right-agent")
    _store(client, left_key, "agent-left", "prn_left", "agr_left", b"left-agent")
    _store(client, right_key, "agent-right", "prn_right", "agr_right", b"right-agent")
    assert client.post("/v1/verify", headers=_auth(left_key), json={"agent_id": "agent-right", "action": _action(10, "act_lr")}).json()["verdict"] == "ALLOW"
    assert client.post("/v1/verify", headers=_auth(right_key), json={"agent_id": "agent-left", "action": _action(10, "act_rl")}).json()["verdict"] == "ALLOW"
    baseline = client.get("/v1/agents/agent-right", headers=_auth(right_key)).json()["score"]
    one_way = client.post(
        "/v1/reports",
        headers=_auth(left_key),
        json={
            "agent_id": "agent-right",
            "kind": "transaction_outcome",
            "outcome": "settled",
            "evidence_hash": "sha256:" + "44" * 32,
            "summary": "Settled one way",
            "action_id": "act_lr",
        },
    )
    assert one_way.status_code == 200, one_way.text
    raised = client.get("/v1/agents/agent-right", headers=_auth(right_key)).json()["score"]
    assert raised > baseline
    closing = client.post(
        "/v1/reports",
        headers=_auth(right_key),
        json={
            "agent_id": "agent-left",
            "kind": "transaction_outcome",
            "outcome": "settled",
            "evidence_hash": "sha256:" + "55" * 32,
            "summary": "Settled the other way",
            "action_id": "act_rl",
        },
    )
    assert closing.status_code == 200, closing.text
    both = client.get("/v1/agents/agent-right", headers=_auth(right_key)).json()
    assert both["score"] == baseline
    assert any(item["code"] == "RING_DISCOUNTED" for item in both["score_reasons"])


def _register_named(client, operator_key: str, agent_id: str, principal_id: str, seed: bytes) -> None:
    agent = private_key_from_seed(hashlib.sha256(seed).digest())
    response = client.post(
        "/v1/agents",
        headers=_auth(operator_key),
        json={
            "agent_id": agent_id,
            "principal_id": principal_id,
            "public_key": agent.public.to_jwk(),
            "verification_level": "operator_verified",
        },
    )
    assert response.status_code == 200, response.text


def _store(client, operator_key: str, agent_id: str, principal_id: str, agreement_id: str, seed: bytes) -> None:
    principal = private_key_from_seed(hashlib.sha256(b"principal-" + seed).digest())
    agent = private_key_from_seed(hashlib.sha256(seed).digest())
    agreement = Agreement.propose(
        agreement_id=agreement_id,
        principal={"display_name": "A Principal", "id": principal_id, "type": "human"},
        agent={"agent_id": agent_id},
        agent_public_key=agent.public,
        intent={
            "allowed_actions": ["purchase"],
            "currency": "CAD",
            "intent_id": "int_" + agent_id,
            "maximum_amount": 1500,
            "purpose": "purchase",
            "time_limit": EXPIRY,
            "version": 1,
        },
        limits={"cumulative_maximum": 2000},
        parent_limits={"cumulative_maximum": 2000, "currency": "CAD", "maximum_amount": 1500},
        actor=Actor("agent", agent_id),
        at=AT,
        expires_at=EXPIRY,
    )
    agreement.accept(principal, AT, confirmed_text=agreement.rendering_preview())
    stored = client.post(
        f"/v1/agents/{agent_id}/intents",
        headers={**_auth(operator_key), "Content-Type": "application/json"},
        content=agreement.to_json(),
    )
    assert stored.status_code == 200, stored.text
