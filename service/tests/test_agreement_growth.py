# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""ALLOW history stays out of the agreement document.

The 10_000-ALLOW run is opt-in (`KATA_RUN_LONG=1`, marker `long`). It uses local
Postgres (GAB_TEST_DATABASE_URL) and records octet_length and pg_column_size of
gab_agreements.document. SYNTHETIC TEST DATA.
"""

from __future__ import annotations

import json
import os
import statistics
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from kata_intent import Actor, Agreement
from kata_service.agreement_ledger import AGREEMENT_DOCUMENT_MAX_BYTES
from kata_service.bureau import BureauError, MemoryRepo
from kata_service.defenses import ScorePolicy

from tests.test_bureau import AT, EXPIRY, _action, _agent_keys, _agreement, _auth, _client, _key, _org, _register
from tests.test_postgres_path import _database_url, _reset

OUTPUT = Path(__file__).resolve().parent / "output" / "allow_10k.txt"
LOG_EVERY = 1000
ALLOWS = 10_000


def test_replay_frequency_and_document_bound_use_the_side_table():
    client = _client()
    operator = _org(client, "SYNTHETIC TEST DATA", "agent_operator")
    operator_key = _key(client, operator["org_id"])
    _register(client, operator_key)
    stored = client.post(
        "/v1/agents/shopper-01/intents",
        headers={**_auth(operator_key), "Content-Type": "application/json"},
        content=_agreement().to_json(),
    )
    assert stored.status_code == 200, stored.text
    first = client.post(
        "/v1/verify",
        headers=_auth(operator_key),
        json={"agent_id": "shopper-01", "action": _action(10, "act_once")},
    )
    assert first.status_code == 200, first.text
    assert first.json()["verdict"] == "ALLOW"
    replay = client.post(
        "/v1/verify",
        headers=_auth(operator_key),
        json={"agent_id": "shopper-01", "action": _action(10, "act_once")},
    )
    assert replay.status_code == 200, replay.text
    assert replay.json()["verdict"] == "DENY"
    assert replay.json()["reasons"] == ["ACTION_REPLAY"]
    fresh = _action(10, "act_idem")
    fresh["settlement"] = {"idempotency_key": "synthetic-idem-1"}
    idem_first = client.post("/v1/verify", headers=_auth(operator_key), json={"agent_id": "shopper-01", "action": fresh})
    assert idem_first.json()["verdict"] == "ALLOW"
    idem_second = dict(fresh)
    idem_second["action_id"] = "act_idem_2"
    idem_again = client.post(
        "/v1/verify",
        headers=_auth(operator_key),
        json={"agent_id": "shopper-01", "action": idem_second},
    )
    assert idem_again.json()["verdict"] == "DENY"
    assert "ACTION_REPLAY" in idem_again.json()["reasons"]

    record = client.app.state.bureau.repo.get_agreement("agr_test")
    assert record is not None
    assert record["document"]["ledger"] == []
    assert record["document"]["ledger_sequence"] == 2
    assert len(client.app.state.bureau.repo.allows[("agr_test", False)]) == 2

    fat = {"agreement_id": "agr_fat", "ledger": [], "pad": "x" * (AGREEMENT_DOCUMENT_MAX_BYTES + 1)}
    with pytest.raises(BureauError) as caught:
        MemoryRepo().save_agreement(
            {
                "agreement_id": "agr_fat",
                "agent_id": "shopper-01",
                "document": fat,
                "status": "active",
                "updated_at": AT,
            }
        )
    assert caught.value.status == 400
    assert caught.value.message == "agreement document exceeds the size bound"


def test_frequency_limit_uses_the_side_table_count():
    client = _client()
    operator = _org(client, "SYNTHETIC TEST DATA", "agent_operator")
    operator_key = _key(client, operator["org_id"])
    _register(client, operator_key)
    principal, agent = _agent_keys()
    when = (datetime.now(timezone.utc) + timedelta(seconds=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
    agreement = Agreement.propose(
        agreement_id="agr_freq",
        principal={"display_name": "SYNTHETIC TEST DATA", "id": "prn_person", "type": "human"},
        agent={"agent_id": "shopper-01"},
        agent_public_key=agent.public,
        intent={
            "allowed_actions": ["purchase"],
            "currency": "CAD",
            "intent_id": "int_freq",
            "maximum_amount": 100,
            "purpose": "purchase",
            "time_limit": EXPIRY,
            "version": 1,
        },
        limits={"cumulative_maximum": 1000, "frequency": {"max_count": 2, "per": "P1D"}},
        parent_limits={"cumulative_maximum": 1000, "currency": "CAD", "maximum_amount": 100},
        actor=Actor("agent", "shopper-01"),
        at=AT,
        expires_at=EXPIRY,
    )
    agreement.accept(principal, AT, confirmed_text=agreement.rendering_preview())
    stored = client.post(
        "/v1/agents/shopper-01/intents",
        headers={**_auth(operator_key), "Content-Type": "application/json"},
        content=agreement.to_json(),
    )
    assert stored.status_code == 200, stored.text
    for index in (1, 2):
        action = _action(1, f"act_freq_{index}")
        action["proposed_at"] = when
        allowed = client.post("/v1/verify", headers=_auth(operator_key), json={"agent_id": "shopper-01", "action": action})
        assert allowed.status_code == 200, allowed.text
        assert allowed.json()["verdict"] == "ALLOW", allowed.text
    blocked_action = _action(1, "act_freq_3")
    blocked_action["proposed_at"] = when
    blocked = client.post(
        "/v1/verify",
        headers=_auth(operator_key),
        json={"agent_id": "shopper-01", "action": blocked_action},
    )
    assert blocked.status_code == 200, blocked.text
    assert blocked.json()["verdict"] == "DENY"
    assert "FREQUENCY_LIMIT_EXCEEDED" in blocked.json()["reasons"]
    record = client.app.state.bureau.repo.get_agreement("agr_freq")
    assert record["document"]["ledger"] == []
    assert record["document"]["ledger_sequence"] == 2


@pytest.mark.long
@pytest.mark.skipif(os.environ.get("KATA_RUN_LONG") != "1", reason="set KATA_RUN_LONG=1 to run the 10000 ALLOW measurement")
def test_ten_thousand_allows_keep_document_size_and_latency_bounded():
    url = _database_url()
    _reset(url)
    client = _client(
        database_url=url,
        schema_url=url,
        rate_limit_per_minute=ALLOWS + 100,
        verify_rate_limit_per_minute=ALLOWS + 100,
        score_policy=ScorePolicy(velocity=False),
    )
    operator = _org(client, "SYNTHETIC TEST DATA", "agent_operator")
    operator_key = _key(client, operator["org_id"])
    _register(client, operator_key)
    agreement = _agreement(maximum=100, cumulative=ALLOWS + 100)
    stored = client.post(
        "/v1/agents/shopper-01/intents",
        headers={**_auth(operator_key), "Content-Type": "application/json"},
        content=agreement.to_json(),
    )
    assert stored.status_code == 200, stored.text

    samples: list[dict[str, object]] = []
    for number in range(1, ALLOWS + 1):
        action = _action(1, f"act_{number:05d}")
        started = time.perf_counter()
        result = client.post(
            "/v1/verify",
            headers=_auth(operator_key),
            json={"agent_id": "shopper-01", "action": action},
        )
        elapsed_ms = (time.perf_counter() - started) * 1000
        assert result.status_code == 200, result.text
        body = result.json()
        assert body["verdict"] == "ALLOW", body
        if number == 1 or number % LOG_EVERY == 0:
            octet_length, column_size, allow_rows = _measure(url)
            samples.append(
                {
                    "n": number,
                    "octet_length": octet_length,
                    "pg_column_size": column_size,
                    "latency_ms": round(elapsed_ms, 3),
                    "allow_rows": allow_rows,
                    "verdict": body["verdict"],
                }
            )

    lines = [
        "SYNTHETIC TEST DATA",
        "agreement_id=agr_test allows=10000",
        "velocity checks disabled for this run so 10000 ALLOWs are recorded",
        f"bound_bytes={AGREEMENT_DOCUMENT_MAX_BYTES}",
        "n octet_length pg_column_size latency_ms allow_rows verdict",
    ]
    for sample in samples:
        lines.append(
            f"{sample['n']} {sample['octet_length']} {sample['pg_column_size']} "
            f"{sample['latency_ms']} {sample['allow_rows']} {sample['verdict']}"
        )
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text("\n".join(lines) + "\n", encoding="utf-8")

    sizes = [int(sample["octet_length"]) for sample in samples]
    columns = [int(sample["pg_column_size"]) for sample in samples]
    assert max(sizes) <= AGREEMENT_DOCUMENT_MAX_BYTES
    assert max(columns) <= AGREEMENT_DOCUMENT_MAX_BYTES
    assert max(sizes) - min(sizes) <= 256
    assert max(columns) - min(columns) <= 256
    for sample in samples:
        assert sample["allow_rows"] == sample["n"]
    early = [float(sample["latency_ms"]) for sample in samples if int(sample["n"]) <= 3000]
    late = [float(sample["latency_ms"]) for sample in samples if int(sample["n"]) >= 8000]
    assert statistics.median(late) <= statistics.median(early) * 2 + 150

    import psycopg

    with psycopg.connect(url) as conn:
        row = conn.execute(
            "SELECT document FROM gab_agreements WHERE agreement_id = %s AND is_test = false",
            ("agr_test",),
        ).fetchone()
    document = json.loads(row[0])
    assert document["ledger"] == []
    assert document["ledger_sequence"] == ALLOWS


def _measure(url: str) -> tuple[int, int, int]:
    import psycopg

    with psycopg.connect(url) as conn:
        size = conn.execute(
            """
            SELECT octet_length(document), pg_column_size(document)
            FROM gab_agreements
            WHERE agreement_id = %s AND is_test = false
            """,
            ("agr_test",),
        ).fetchone()
        rows = conn.execute(
            "SELECT COUNT(*) FROM gab_agreement_allows WHERE agreement_id = %s AND is_test = false",
            ("agr_test",),
        ).fetchone()
    return int(size[0]), int(size[1]), int(rows[0])
