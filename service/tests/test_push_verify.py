# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Pushed revocations and /v1/verify. SYNTHETIC TEST DATA.

The baseline commit recorded that a stored push left verify at ALLOW.
These tests cover the fail-closed behavior after that finding.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from fastapi.testclient import TestClient

from kata_intent import Actor, Agreement, private_key_from_seed
from kata_intent.revocation import sign_revocation_push

from kata_service.asgi import create_app
from kata_service.store import MemoryStore
from tests.test_bureau import AT, EXPIRY, _action, _agent_keys, _agreement, _auth, _key, _org, _register, _settings
from tests.test_postgres_path import _database_url, _reset

OUTPUT = Path(__file__).resolve().parent / "output"
PUSH_AT = "2026-10-04T18:01:00Z"
REVOKE_AT = "2026-10-04T18:00:00Z"


def _notifier():
    return private_key_from_seed(b"n" * 32)


def _client(database_url: str | None = None, store=None) -> tuple[TestClient, object]:
    notifier = _notifier()
    settings = _settings(
        database_url=database_url,
        schema_url=database_url,
        log_signing_seed=hashlib.sha256(b"push-verify-log").digest(),
        push_notifier_jwk=notifier.public.to_jwk(),
        rate_limit_per_minute=1000,
        verify_rate_limit_per_minute=1000,
    )
    if store is None:
        if database_url:
            from kata_service.store import PostgresStore

            store = PostgresStore(database_url, database_url)
        else:
            store = MemoryStore()
    return TestClient(create_app(settings, store)), notifier


def _store(client: TestClient, operator_key: str, agent_id: str, agreement: Agreement) -> None:
    stored = client.post(
        f"/v1/agents/{agent_id}/intents",
        headers={**_auth(operator_key), "Content-Type": "application/json"},
        content=agreement.to_json(),
    )
    assert stored.status_code == 200, stored.text


def _verify(client: TestClient, operator_key: str, agent_id: str, action_id: str, agreement_id: str):
    return client.post(
        "/v1/verify",
        headers=_auth(operator_key),
        json={
            "agent_id": agent_id,
            "agreement_id": agreement_id,
            "action": _action(10, action_id),
        },
    )


def _sequence(client: TestClient, agreement_id: str) -> int:
    document = client.app.state.bureau.repo.get_agreement(agreement_id)["document"]
    return int(document.get("ledger_sequence") or 0)


def _other_agent_agreement() -> Agreement:
    principal = private_key_from_seed(hashlib.sha256(b"other-principal").digest())
    agent = private_key_from_seed(hashlib.sha256(b"other-agent").digest())
    agreement = Agreement.propose(
        agreement_id="agr_far",
        principal={"display_name": "SYNTHETIC TEST DATA", "id": "prn_other", "type": "human"},
        agent={"agent_id": "shopper-02"},
        agent_public_key=agent.public,
        intent={
            "allowed_actions": ["purchase"],
            "currency": "CAD",
            "intent_id": "int_other",
            "maximum_amount": 1500,
            "purpose": "purchase",
            "time_limit": EXPIRY,
            "version": 1,
        },
        limits={"cumulative_maximum": 2000},
        parent_limits={"cumulative_maximum": 2000, "currency": "CAD", "maximum_amount": 1500},
        actor=Actor("agent", "shopper-02"),
        at=AT,
        expires_at=EXPIRY,
    )
    agreement.accept(principal, AT, confirmed_text=agreement.rendering_preview())
    return agreement


def _push(client: TestClient, notifier, agreement: Agreement):
    principal, _agent = _agent_keys()
    revocation = agreement.revoke(principal, REVOKE_AT)
    notice = sign_revocation_push(revocation, notifier, PUSH_AT)
    return client.post("/v1/revocations/push", json=notice), notice


def _assert_deny(response) -> None:
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["verdict"] == "DENY"
    assert body["reasons"] == ["MANDATE_REVOKED"]
    assert body["messages"] == ["A trusted revocation log says the principal revoked this mandate."]


def _run(client: TestClient, notifier) -> dict:
    operator = _org(client, "SYNTHETIC TEST DATA", "agent_operator")
    operator_key = _key(client, operator["org_id"])
    _register(client, operator_key)
    target = _agreement()
    other = _agreement(agreement_id="agr_other", intent_id="int_other_same")
    _store(client, operator_key, "shopper-01", target)
    _store(client, operator_key, "shopper-01", other)
    far = _other_agent_agreement()
    other_agent = private_key_from_seed(hashlib.sha256(b"other-agent").digest())
    registered = client.post(
        "/v1/agents",
        headers=_auth(operator_key),
        json={
            "agent_id": "shopper-02",
            "principal_id": "prn_other",
            "public_key": other_agent.public.to_jwk(),
            "verification_level": "operator_verified",
        },
    )
    assert registered.status_code == 200, registered.text
    _store(client, operator_key, "shopper-02", far)

    before = _verify(client, operator_key, "shopper-01", "act_before", "agr_test")
    assert before.status_code == 200, before.text
    assert before.json()["verdict"] == "ALLOW"
    pushed, notice = _push(client, notifier, target)
    assert pushed.status_code == 200, pushed.text
    assert pushed.json()["stored"] is True
    denied = _verify(client, operator_key, "shopper-01", "act_revoked", "agr_test")
    _assert_deny(denied)
    same_agent = _verify(client, operator_key, "shopper-01", "act_same_agent", "agr_other")
    other_agent_verify = _verify(client, operator_key, "shopper-02", "act_other_agent", "agr_far")
    again = client.post("/v1/revocations/push", json=notice)
    replay = _verify(client, operator_key, "shopper-01", "act_replay", "agr_test")
    _assert_deny(replay)
    listed = client.get("/v1/revocations")
    return {
        "label": "SYNTHETIC TEST DATA",
        "before": before.json()["verdict"],
        "push_stored": pushed.json()["stored"],
        "revoked": denied.json(),
        "same_agent_other_agreement": same_agent.json()["verdict"],
        "other_agent": other_agent_verify.json()["verdict"],
        "replay_push_stored": again.json()["stored"],
        "replay_verify": replay.json()["verdict"],
        "listed": len(listed.json()["revocations"]),
        "revoked_sequence": _sequence(client, "agr_test"),
        "same_agent_sequence": _sequence(client, "agr_other"),
        "other_agent_sequence": _sequence(client, "agr_far"),
    }


def _assert_closed(payload: dict) -> None:
    assert payload["before"] == "ALLOW"
    assert payload["push_stored"] is True
    assert payload["revoked"]["verdict"] == "DENY"
    assert payload["revoked"]["reasons"] == ["MANDATE_REVOKED"]
    assert payload["same_agent_other_agreement"] == "ALLOW"
    assert payload["other_agent"] == "ALLOW"
    assert payload["replay_push_stored"] is False
    assert payload["replay_verify"] == "DENY"
    assert payload["listed"] == 1
    assert payload["revoked_sequence"] == 1
    assert payload["same_agent_sequence"] == 1
    assert payload["other_agent_sequence"] == 1


def _write(name: str, payload: dict) -> None:
    OUTPUT.mkdir(exist_ok=True)
    (OUTPUT / name).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def test_pushed_revocation_denies_and_leaves_unrelated_allows_on_memory():
    client, notifier = _client()
    payload = _run(client, notifier)
    _write("push_verify_after_memory.txt", payload)
    _assert_closed(payload)


def test_pushed_revocation_denies_and_leaves_unrelated_allows_on_postgres():
    url = _database_url()
    _reset(url)
    client, notifier = _client(url)
    payload = _run(client, notifier)
    _write("push_verify_after_postgres.txt", payload)
    _assert_closed(payload)


def test_unreadable_revocation_list_denies_verify():
    class Down(MemoryStore):
        def list_revocations(self):
            raise RuntimeError("SYNTHETIC TEST DATA revocation list down")

    client, _notifier = _client(store=Down())
    operator = _org(client, "SYNTHETIC TEST DATA", "agent_operator")
    operator_key = _key(client, operator["org_id"])
    _register(client, operator_key)
    _store(client, operator_key, "shopper-01", _agreement())
    response = _verify(client, operator_key, "shopper-01", "act_down", "agr_test")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["verdict"] == "DENY"
    assert body["reasons"] == ["REVOCATION_LIST_UNAVAILABLE"]
    assert body["messages"] == ["The revocation list could not be pulled."]
    assert "revocation list down" not in response.text
    assert _sequence(client, "agr_test") == 0
