# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Whether a pushed revocation changes /v1/verify. SYNTHETIC TEST DATA.

This file records the behavior of the current service. The push is signed
with a local Ed25519 notifier key. The inner revocation is signed with the
same principal key that signed the stored agreement.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from fastapi.testclient import TestClient

from kata_intent.revocation import sign_revocation_push

from kata_service.asgi import create_app
from kata_service.store import MemoryStore
from tests.test_bureau import AT, _action, _agent_keys, _agreement, _auth, _key, _org, _register, _settings
from tests.test_postgres_path import _database_url, _reset

OUTPUT = Path(__file__).resolve().parent / "output"
PUSH_AT = "2026-10-04T18:01:00Z"
REVOKE_AT = "2026-10-04T18:00:00Z"


def _notifier():
    from kata_intent import private_key_from_seed

    return private_key_from_seed(b"n" * 32)


def _client(database_url: str | None = None) -> tuple[TestClient, object]:
    notifier = _notifier()
    settings = _settings(
        database_url=database_url,
        schema_url=database_url,
        log_signing_seed=hashlib.sha256(b"push-verify-log").digest(),
        push_notifier_jwk=notifier.public.to_jwk(),
        rate_limit_per_minute=1000,
        verify_rate_limit_per_minute=1000,
    )
    if database_url:
        from kata_service.store import PostgresStore

        store = PostgresStore(database_url, database_url)
    else:
        store = MemoryStore()
    return TestClient(create_app(settings, store)), notifier


def _observe(client: TestClient, notifier) -> dict:
    operator = _org(client, "SYNTHETIC TEST DATA", "agent_operator")
    operator_key = _key(client, operator["org_id"])
    _register(client, operator_key)
    agreement = _agreement()
    stored = client.post(
        "/v1/agents/shopper-01/intents",
        headers={**_auth(operator_key), "Content-Type": "application/json"},
        content=agreement.to_json(),
    )
    assert stored.status_code == 200, stored.text
    before = client.post(
        "/v1/verify",
        headers=_auth(operator_key),
        json={"agent_id": "shopper-01", "action": _action(10, "act_before")},
    )
    principal, _agent = _agent_keys()
    revocation = agreement.revoke(principal, REVOKE_AT)
    notice = sign_revocation_push(revocation, notifier, PUSH_AT)
    pushed = client.post("/v1/revocations/push", json=notice)
    listed = client.get("/v1/revocations")
    after = client.post(
        "/v1/verify",
        headers=_auth(operator_key),
        json={"agent_id": "shopper-01", "action": _action(10, "act_after")},
    )
    document = client.app.state.bureau.repo.get_agreement("agr_test")["document"]
    return {
        "label": "SYNTHETIC TEST DATA",
        "stored_intent": stored.status_code,
        "before": {"status": before.status_code, "body": before.json()},
        "push": {"status": pushed.status_code, "body": pushed.json()},
        "listed_agreement_ids": [item.get("agreement_id") for item in listed.json()["revocations"]],
        "after": {"status": after.status_code, "body": after.json()},
        "ledger_sequence": document.get("ledger_sequence"),
        "ledger_len": len(document.get("ledger") or []),
    }


def _write(name: str, payload: dict) -> None:
    OUTPUT.mkdir(exist_ok=True)
    (OUTPUT / name).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _assert_current(payload: dict) -> None:
    assert payload["before"]["status"] == 200
    assert payload["before"]["body"]["verdict"] == "ALLOW"
    assert payload["push"]["status"] == 200
    assert payload["push"]["body"]["stored"] is True
    assert payload["listed_agreement_ids"] == ["agr_test"]
    assert payload["after"]["status"] == 200
    assert payload["after"]["body"]["verdict"] == "ALLOW"
    assert "MANDATE_REVOKED" not in (payload["after"]["body"].get("reasons") or [])
    assert payload["ledger_sequence"] == 2
    assert payload["ledger_len"] == 2


def test_pushed_revocation_leaves_verify_allow_on_memory():
    client, notifier = _client()
    payload = _observe(client, notifier)
    _write("push_verify_baseline_memory.txt", payload)
    _assert_current(payload)


def test_pushed_revocation_leaves_verify_allow_on_postgres():
    url = _database_url()
    _reset(url)
    client, notifier = _client(url)
    payload = _observe(client, notifier)
    _write("push_verify_baseline_postgres.txt", payload)
    _assert_current(payload)
