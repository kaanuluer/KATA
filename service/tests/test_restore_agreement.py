# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""POST /v1/agents/{id}/intents rejects an agreement id that is already stored.

A second store used to replace the agreement document and the side-table ALLOW
rows. SYNTHETIC TEST DATA. Local Postgres only when GAB_TEST_DATABASE_URL is set.
"""

from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from tests.test_bureau import _action, _agreement, _auth, _client, _key, _org, _register
from tests.test_postgres_path import _database_url, _reset

OUTPUT = Path(__file__).resolve().parent / "output" / "restore_agreement.txt"


def _allows(client: TestClient, agreement_id: str) -> list[dict[str, object]]:
    repo = client.app.state.bureau.repo
    memory = getattr(repo, "allows", None)
    if memory is not None:
        rows = memory.get((agreement_id, False), [])
        return [
            {"action_id": item.get("action_id"), "sequence": item.get("sequence"), "outcome": item.get("outcome")}
            for item in rows
        ]
    fetched = repo._all(
        """
        SELECT action_id, sequence, outcome
        FROM gab_agreement_allows
        WHERE agreement_id = %s AND is_test = false
        ORDER BY sequence
        """,
        (agreement_id,),
    )
    return [{"action_id": row[0], "sequence": row[1], "outcome": row[2]} for row in fetched]


def _state(client: TestClient, agreement_id: str) -> dict[str, object]:
    document = client.app.state.bureau.repo.get_agreement(agreement_id)["document"]
    return {
        "ledger": document.get("ledger"),
        "ledger_sequence": document.get("ledger_sequence"),
        "ledger_head": document.get("ledger_head"),
        "spend_summary": document.get("spend_summary"),
        "allows": _allows(client, agreement_id),
    }


def _scenario(client: TestClient) -> dict[str, object]:
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
    allowed = client.post(
        "/v1/verify",
        headers=_auth(operator_key),
        json={"agent_id": "shopper-01", "agreement_id": "agr_test", "action": _action(10, "act_once")},
    )
    assert allowed.status_code == 200, allowed.text
    assert allowed.json()["verdict"] == "ALLOW", allowed.text
    before = _state(client, "agr_test")

    again = client.post(
        "/v1/agents/shopper-01/intents",
        headers={**_auth(operator_key), "Content-Type": "application/json"},
        content=agreement.to_json(),
    )
    mutated = json.loads(agreement.to_json())
    mutated["mandates"][0]["intent"]["maximum_amount"] = 1
    changed = client.post(
        "/v1/agents/shopper-01/intents",
        headers={**_auth(operator_key), "Content-Type": "application/json"},
        content=json.dumps(mutated),
    )
    after = _state(client, "agr_test")
    replay = client.post(
        "/v1/verify",
        headers=_auth(operator_key),
        json={"agent_id": "shopper-01", "agreement_id": "agr_test", "action": _action(10, "act_once")},
    )
    after_replay = _state(client, "agr_test")
    fresh = _agreement(agreement_id="agr_next", intent_id="int_next")
    created = client.post(
        "/v1/agents/shopper-01/intents",
        headers={**_auth(operator_key), "Content-Type": "application/json"},
        content=fresh.to_json(),
    )
    return {
        "label": "SYNTHETIC TEST DATA",
        "first_store": stored.status_code,
        "first_verify": allowed.json()["verdict"],
        "restored_status": again.status_code,
        "restored_body": again.json(),
        "mutated_status": changed.status_code,
        "mutated_body": changed.json(),
        "before": before,
        "after_restore": after,
        "replay_status": replay.status_code,
        "replay_body": {"verdict": replay.json()["verdict"], "reasons": replay.json()["reasons"]},
        "after_replay": after_replay,
        "new_agreement_status": created.status_code,
        "new_agreement_id": created.json().get("agreement_id") if created.status_code == 200 else None,
        "original_after_new": _state(client, "agr_test"),
    }


def _assert_rejected(payload: dict[str, object]) -> None:
    assert payload["first_store"] == 200
    assert payload["first_verify"] == "ALLOW"
    assert payload["restored_status"] == 409
    assert payload["restored_body"] == {"error": "agreement_id is already stored"}
    assert payload["mutated_status"] == 409
    assert payload["mutated_body"] == {"error": "agreement_id is already stored"}
    assert payload["after_restore"] == payload["before"]
    assert payload["replay_status"] == 200
    assert payload["replay_body"] == {"verdict": "DENY", "reasons": ["ACTION_REPLAY"]}
    assert payload["after_replay"] == payload["before"]
    assert payload["new_agreement_status"] == 200
    assert payload["new_agreement_id"] == "agr_next"
    assert payload["original_after_new"] == payload["before"]
    allows = payload["before"]["allows"]
    assert allows == [{"action_id": "act_once", "sequence": 1, "outcome": "allowed"}]
    assert payload["before"]["ledger"] == []
    assert payload["before"]["ledger_sequence"] == 1


def _record(name: str, payload: dict[str, object]) -> None:
    OUTPUT.parent.mkdir(exist_ok=True)
    recorded = json.loads(OUTPUT.read_text(encoding="utf-8")) if OUTPUT.exists() else {}
    recorded[name] = payload
    OUTPUT.write_text(json.dumps(recorded, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")


def test_restoring_an_agreement_id_is_rejected_on_memory():
    payload = _scenario(_client())
    _assert_rejected(payload)
    _record("memory", payload)


def test_restoring_an_agreement_id_is_rejected_on_postgres():
    url = _database_url()
    _reset(url)
    payload = _scenario(_client(database_url=url, schema_url=url))
    _assert_rejected(payload)
    _record("postgres", payload)
