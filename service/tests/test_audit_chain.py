# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""gab_audit row hash chain. SYNTHETIC TEST DATA.

A changed path, a deleted first row, a deleted middle row, a deleted last row,
and reordered links were detected in this test. The hash is not keyed. Someone
with database write access can recompute the chain from the start node.
"""

from __future__ import annotations

import psycopg

from kata_service.audit_chain import AUDIT_CHAIN_START
from kata_service.bureau_pg import PostgresRepo
from tests.test_postgres_path import _database_url, _reset


def _insert_unlinked(url: str, audit_id: str, at: str, path: str) -> None:
    with psycopg.connect(url) as conn:
        conn.execute(
            """
            INSERT INTO gab_audit (
              audit_id, at, org_id, key_id, method, path, status, purpose_code, agent_id, environment
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (audit_id, at, "org_synthetic", None, "POST", path, 200, None, "shopper-01", "live"),
        )


def _linked(url: str) -> PostgresRepo:
    repo = PostgresRepo(url, url)
    repo.migration_versions()
    _insert_unlinked(url, "aud_one", "2026-10-17T00:00:01Z", "/v1/verify")
    _insert_unlinked(url, "aud_two", "2026-10-17T00:00:02Z", "/v1/agents/shopper-01")
    repo._link_existing_audit()
    repo.add_audit(
        {
            "audit_id": "aud_three",
            "at": "2026-10-17T00:00:03Z",
            "org_id": "org_synthetic",
            "method": "POST",
            "path": "/v1/verify",
            "status": 200,
            "agent_id": "shopper-01",
            "environment": "live",
        }
    )
    assert repo.audit_chain() == {"ok": True, "rows": 3, "start": AUDIT_CHAIN_START}
    return repo


def test_existing_rows_link_from_the_start_node_and_a_change_is_detected():
    url = _database_url()
    _reset(url)
    repo = PostgresRepo(url, url)
    repo.migration_versions()
    _insert_unlinked(url, "aud_one", "2026-10-17T00:00:01Z", "/v1/verify")
    _insert_unlinked(url, "aud_two", "2026-10-17T00:00:02Z", "/v1/agents/shopper-01")
    repo._link_existing_audit()
    linked = repo.audit_chain()
    assert linked == {"ok": True, "rows": 2, "start": AUDIT_CHAIN_START}
    with psycopg.connect(url) as conn:
        first = conn.execute(
            "SELECT prev_hash FROM gab_audit WHERE audit_id = %s",
            ("aud_one",),
        ).fetchone()
        tail = conn.execute("SELECT tail_hash FROM gab_audit_tail WHERE singleton = 1").fetchone()
    assert first[0] == AUDIT_CHAIN_START
    assert tail is not None

    repo.add_audit(
        {
            "audit_id": "aud_three",
            "at": "2026-10-17T00:00:03Z",
            "org_id": "org_synthetic",
            "method": "POST",
            "path": "/v1/verify",
            "status": 200,
            "agent_id": "shopper-01",
            "environment": "live",
        }
    )
    assert repo.audit_chain()["ok"] is True
    assert repo.audit_chain()["rows"] == 3

    with psycopg.connect(url) as conn:
        conn.execute("UPDATE gab_audit SET path = %s WHERE audit_id = %s", ("/changed", "aud_two"))
    broken = repo.audit_chain()
    assert broken["ok"] is False, "changed path was not detected in this test"
    assert broken["audit_id"] == "aud_two"
    assert broken["break"] == "hash does not match the row"
    assert broken["rows"] == 3


def test_deleting_the_first_row_is_detected():
    url = _database_url()
    _reset(url)
    repo = _linked(url)
    with psycopg.connect(url) as conn:
        conn.execute("DELETE FROM gab_audit WHERE audit_id = %s", ("aud_one",))
    broken = repo.audit_chain()
    assert broken["ok"] is False, "deleted first row was not detected in this test"
    assert broken["break"] == "start node is missing"
    assert broken["rows"] == 2


def test_deleting_a_middle_row_is_detected():
    url = _database_url()
    _reset(url)
    repo = _linked(url)
    with psycopg.connect(url) as conn:
        conn.execute("DELETE FROM gab_audit WHERE audit_id = %s", ("aud_two",))
    broken = repo.audit_chain()
    assert broken["ok"] is False, "deleted middle row was not detected in this test"
    assert broken["audit_id"] == "aud_three"
    assert broken["break"] == "row is not linked from the start node"
    assert broken["rows"] == 2


def test_deleting_the_last_row_is_detected():
    url = _database_url()
    _reset(url)
    repo = _linked(url)
    with psycopg.connect(url) as conn:
        conn.execute("DELETE FROM gab_audit WHERE audit_id = %s", ("aud_three",))
    broken = repo.audit_chain()
    assert broken["ok"] is False, "deleted last row was not detected in this test"
    assert broken["break"] == "tail pointer does not match the last linked row"
    assert broken["rows"] == 2


def test_reordered_links_are_detected():
    url = _database_url()
    _reset(url)
    repo = _linked(url)
    with psycopg.connect(url) as conn:
        conn.execute(
            """
            UPDATE gab_audit AS row
            SET prev_hash = other.prev_hash, hash = other.hash
            FROM gab_audit AS other
            WHERE row.audit_id IN ('aud_two', 'aud_three')
              AND other.audit_id IN ('aud_two', 'aud_three')
              AND row.audit_id <> other.audit_id
            """
        )
    broken = repo.audit_chain()
    assert broken["ok"] is False, "reordered links were not detected in this test"
    assert broken["audit_id"] == "aud_three"
    assert broken["break"] == "hash does not match the row"
