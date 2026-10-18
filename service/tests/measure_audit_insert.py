# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Time one gab_audit insert at about 300 rows and about 12000 rows.

Not collected by pytest. SYNTHETIC TEST DATA. synthetic data, shared VM,
loopback, no upstream. The hash is not keyed. Someone with database write
access can recompute the chain from the start node.

Prints nothing that contains the database URL.
"""

from __future__ import annotations

import statistics
import time
from pathlib import Path

import psycopg

from kata_service.audit_chain import AUDIT_CHAIN_START, audit_row_hash
from kata_service.bureau_pg import PostgresRepo
from tests.test_postgres_path import _database_url, _reset

OUTPUT = Path(__file__).resolve().parent / "output" / "audit_insert_times.txt"
LABEL = "synthetic data, shared VM, loopback, no upstream"
SCAN = """
SELECT hash FROM gab_audit
WHERE hash IS NOT NULL
  AND NOT EXISTS (
    SELECT 1 FROM gab_audit AS child WHERE child.prev_hash = gab_audit.hash
  )
"""


def _stored(number: int) -> dict[str, object]:
    return {
        "audit_id": f"aud_{number:06d}",
        "at": f"2026-10-17T00:{number // 60:02d}:{number % 60:02d}Z" if number < 3600 else f"2026-10-17T{number // 3600:02d}:{(number // 60) % 60:02d}:{number % 60:02d}Z",
        "org_id": "org_synthetic",
        "key_id": None,
        "method": "POST",
        "path": "/v1/verify",
        "status": 200,
        "purpose_code": None,
        "agent_id": "shopper-01",
        "environment": "live",
    }


def _bulk(url: str, start: int, count: int, prev: str) -> str:
    rows = []
    for number in range(start, start + count):
        stored = _stored(number)
        digest = audit_row_hash(prev, stored)
        rows.append(
            (
                stored["audit_id"],
                stored["at"],
                stored["org_id"],
                stored["key_id"],
                stored["method"],
                stored["path"],
                stored["status"],
                stored["purpose_code"],
                stored["agent_id"],
                stored["environment"],
                prev,
                digest,
            )
        )
        prev = digest
    with psycopg.connect(url) as conn:
        with conn.cursor() as cur:
            cur.executemany(
                """
                INSERT INTO gab_audit (
                  audit_id, at, org_id, key_id, method, path, status, purpose_code, agent_id, environment,
                  prev_hash, hash
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                rows,
            )
        conn.execute(
            """
            INSERT INTO gab_audit_tail (singleton, tail_hash) VALUES (1, %s)
            ON CONFLICT (singleton) DO UPDATE SET tail_hash = EXCLUDED.tail_hash
            """,
            (prev,),
        )
    return prev


def _time_insert(repo: PostgresRepo, number: int) -> float:
    started = time.perf_counter()
    repo.add_audit(_stored(number))
    return (time.perf_counter() - started) * 1000


def _time_scan(url: str) -> float:
    with psycopg.connect(url) as conn:
        started = time.perf_counter()
        found = conn.execute(SCAN).fetchall()
        elapsed = (time.perf_counter() - started) * 1000
    if len(found) != 1:
        raise SystemExit(f"scan tails={len(found)}")
    return elapsed


def main() -> None:
    url = _database_url()
    _reset(url)
    repo = PostgresRepo(url, url)
    repo.migration_versions()
    lines = [
        LABEL,
        "SYNTHETIC TEST DATA",
        "insert path reads gab_audit_tail under the audit lock",
        "scan is the previous NOT EXISTS tail lookup, timed once at the same size",
        "hash is not keyed; a database writer can recompute the chain from the start node",
    ]
    prev = AUDIT_CHAIN_START
    timed_from = 0
    for size in (300, 12000):
        prev = _bulk(url, timed_from, size - timed_from, prev)
        timed_from = size
        samples = [_time_insert(repo, size + offset) for offset in range(15)]
        timed_from = size + 15
        prev_row = None
        with psycopg.connect(url) as conn:
            prev_row = conn.execute("SELECT tail_hash FROM gab_audit_tail WHERE singleton = 1").fetchone()
            count = conn.execute("SELECT COUNT(*) FROM gab_audit").fetchone()[0]
        lines.append(
            "size_before={size} rows_after={count} insert_ms={samples} "
            "min_ms={low:.3f} p50_ms={p50:.3f} max_ms={high:.3f} tail_set={tail} scan_ms={scan:.3f}".format(
                size=size,
                count=count,
                samples=[round(item, 3) for item in samples],
                low=min(samples),
                p50=statistics.median(samples),
                high=max(samples),
                tail=prev_row is not None,
                scan=_time_scan(url),
            )
        )
        with psycopg.connect(url) as conn:
            prev = conn.execute("SELECT tail_hash FROM gab_audit_tail WHERE singleton = 1").fetchone()[0]
    text = "\n".join(lines) + "\n"
    OUTPUT.parent.mkdir(exist_ok=True)
    OUTPUT.write_text(text, encoding="utf-8")
    print(text, end="")


if __name__ == "__main__":
    main()
