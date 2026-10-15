# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Collusion detection beyond a cycle of four."""

from __future__ import annotations

import hashlib

from kata_intent import Actor, Agreement, private_key_from_seed

from kata_service.defenses import cluster_edges

from test_bureau import AT, EXPIRY, _action, _auth, _client, _key, _org


def test_cluster_edges_cover_long_cycles_one_way_reporters_and_dense_volume():
    cycle = {("a", "b"), ("b", "c"), ("c", "d"), ("d", "e"), ("e", "a")}
    assert cluster_edges(cycle) == cycle
    one_way = {("merchant", "operator")}
    assert ("merchant", "operator") in cluster_edges(one_way, shared_groups=[{"merchant", "operator"}])
    fan = {("merchant", "operator"), ("partner", "operator")}
    dense = [("merchant", "operator", 50.0), ("operator", "partner", 50.0), ("partner", "merchant", 50.0)]
    assert fan <= cluster_edges(fan, volumes=dense)
    leaked = dense + [("operator", "outside", 1000.0)]
    assert ("merchant", "operator") not in cluster_edges(fan, volumes=leaked)


def test_a_five_cycle_does_not_keep_settled_credit():
    client = _client()
    keys = []
    for index in range(5):
        org = _org(client, f"Operator {index}", "agent_operator")
        keys.append(_key(client, org["org_id"]))
        _register_cycle(client, keys[index], index)
    baselines = [
        client.get(f"/v1/agents/agent-{index}", headers=_auth(keys[index])).json()["score"] for index in range(5)
    ]
    for index in range(5):
        subject = (index + 1) % 5
        allowed = client.post(
            "/v1/verify",
            headers=_auth(keys[index]),
            json={"agent_id": f"agent-{subject}", "action": _action(10, f"act_{index}")},
        )
        assert allowed.json()["verdict"] == "ALLOW", allowed.text
        filed = client.post(
            "/v1/reports",
            headers=_auth(keys[index]),
            json={
                "agent_id": f"agent-{subject}",
                "kind": "transaction_outcome",
                "outcome": "settled",
                "evidence_hash": "sha256:" + f"{index:02x}" * 32,
                "summary": "Settled around the ring",
                "action_id": f"act_{index}",
            },
        )
        assert filed.status_code == 200, filed.text
    for index in range(5):
        body = client.get(f"/v1/agents/agent-{index}", headers=_auth(keys[index])).json()
        assert body["score"] == baselines[index]
        assert any(item["code"] == "RING_DISCOUNTED" for item in body["score_reasons"])


def test_a_shared_signal_discounts_a_one_way_reporter():
    client = _client()
    operator = _org(client, "Harbor Agents", "agent_operator")
    merchant = _org(client, "Techstore", "merchant")
    operator_key = _key(client, operator["org_id"])
    merchant_key = _key(client, merchant["org_id"])
    client.app.state.bureau.repo.set_org_created_at(merchant["org_id"], "2020-01-01T00:00:00Z")
    _register_cycle(client, operator_key, 0, agent_id="shopper-01", principal_id="prn_person", device_signal="same-desk")
    baseline = client.get("/v1/agents/shopper-01", headers=_auth(operator_key)).json()["score"]
    allowed = client.post(
        "/v1/verify",
        headers=_auth(merchant_key),
        json={"agent_id": "shopper-01", "action": _action(10, "act_one_way")},
    )
    assert allowed.json()["verdict"] == "ALLOW"
    filed = client.post(
        "/v1/reports",
        headers=_auth(merchant_key),
        json={
            "agent_id": "shopper-01",
            "kind": "transaction_outcome",
            "outcome": "settled",
            "evidence_hash": "sha256:" + "ab" * 32,
            "summary": "One-way settled",
            "action_id": "act_one_way",
            "shared_signal": "same-desk",
        },
    )
    assert filed.status_code == 200, filed.text
    body = client.get("/v1/agents/shopper-01", headers=_auth(operator_key)).json()
    assert body["score"] == baseline
    assert any(item["code"] == "RING_DISCOUNTED" for item in body["score_reasons"])


def _register_cycle(client, operator_key: str, index: int, agent_id: str | None = None, principal_id: str | None = None, device_signal: str | None = None) -> None:
    agent_id = agent_id or f"agent-{index}"
    principal_id = principal_id or f"prn_{index}"
    seed = hashlib.sha256(f"cycle-{agent_id}".encode()).digest()
    agent = private_key_from_seed(seed)
    body = {
        "agent_id": agent_id,
        "principal_id": principal_id,
        "public_key": agent.public.to_jwk(),
        "verification_level": "operator_verified",
    }
    if device_signal:
        body["device_signal"] = device_signal
    created = client.post("/v1/agents", headers=_auth(operator_key), json=body)
    assert created.status_code == 200, created.text
    principal = private_key_from_seed(hashlib.sha256(b"principal-" + seed).digest())
    agreement = Agreement.propose(
        agreement_id=f"agr_{agent_id}",
        principal={"display_name": "A Principal", "id": principal_id, "type": "human"},
        agent={"agent_id": agent_id},
        agent_public_key=agent.public,
        intent={
            "allowed_actions": ["purchase"],
            "currency": "CAD",
            "intent_id": f"int_{agent_id}",
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
