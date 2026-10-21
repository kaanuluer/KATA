# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Offline copy of gab_push_devices.consent_at into gab_consent_events.

Ship this unexecuted. Dry-run does not open a database. A write needs
--execute, --approve, a verified backup id, a verified backup time, and the
phrase BACKUP-VERIFIED.

Rollback: restore the verified backup named by --backup-confirmed-id. The
consent table is append-only, so this script cannot delete the rows it inserts.
Do not drop the trigger as a rollback.

The script prints counts only. It does not print endpoints or addresses.
This is not a compliance claim or a certification.
"""

from __future__ import annotations

import argparse
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable

from kata_service.consent import notice, seal_event

BACKUP_PHRASE = "BACKUP-VERIFIED"
ROLLBACK_NOTE = (
    "Rollback: restore the verified backup passed as --backup-confirmed-id. "
    "gab_consent_events is append-only, so inserted events cannot be deleted in place. "
    "Do not drop the append-only trigger as a rollback."
)
_STAMP = re.compile(r"^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}(:\d{2})?Z)?$")


@dataclass(frozen=True)
class CopyArgs:
    execute: bool
    approve: bool
    backup_id: str
    backup_at: str
    backup_phrase: str
    database_url: str


@dataclass(frozen=True)
class CopyPlan:
    scanned: int
    insert: int
    skip: int
    actions: tuple[dict[str, Any], ...]


def parse_args(argv: list[str] | None = None) -> CopyArgs:
    parser = argparse.ArgumentParser(description="Copy push consent timestamps into consent events. Dry-run unless --execute.")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--approve", action="store_true")
    parser.add_argument("--backup-confirmed-id", default="")
    parser.add_argument("--backup-confirmed-at", default="")
    parser.add_argument("--backup-phrase", default="")
    parser.add_argument("--database-url", default="")
    parsed = parser.parse_args(argv)
    return CopyArgs(
        execute=parsed.execute,
        approve=parsed.approve,
        backup_id=parsed.backup_confirmed_id.strip(),
        backup_at=parsed.backup_confirmed_at.strip(),
        backup_phrase=parsed.backup_phrase.strip(),
        database_url=parsed.database_url.strip(),
    )


def gate_errors(args: CopyArgs) -> list[str]:
    if not args.execute:
        return []
    errors = []
    if not args.approve:
        errors.append("missing --approve")
    if len(args.backup_id) < 8 or args.backup_id.lower() in {"none", "n/a", "na", "later", "todo"}:
        errors.append("missing a verified --backup-confirmed-id")
    if not _STAMP.match(args.backup_at):
        errors.append("missing a verified --backup-confirmed-at timestamp")
    elif args.backup_at[:10] > datetime.now(timezone.utc).date().isoformat():
        errors.append("--backup-confirmed-at is in the future")
    if args.backup_phrase != BACKUP_PHRASE:
        errors.append(f"--backup-phrase must be {BACKUP_PHRASE}")
    if not args.database_url:
        errors.append("missing --database-url")
    return errors


def plan_rows(devices: Iterable[dict[str, Any]], existing_refs: Iterable[str], *, event_id_for) -> CopyPlan:
    """Plan inserts from device rows. ``event_id_for`` supplies a new id per insert."""

    known = {item for item in existing_refs if item}
    text = notice("push")
    actions = []
    scanned = 0
    skip = 0
    for row in devices:
        scanned += 1
        device_id = str(row.get("device_id") or "")
        principal_id = str(row.get("principal_id") or "")
        at = str(row.get("consent_at") or "")
        if not device_id or not principal_id or not at or device_id in known:
            skip += 1
            continue
        known.add(device_id)
        actions.append(
            {
                "event_id": event_id_for(device_id),
                "principal_id": principal_id,
                "purpose": "push",
                "granted": True,
                "text_version": text["text_version"],
                "text_sha256": text["text_sha256"],
                "at": at,
                "source_ref": device_id,
            }
        )
    return CopyPlan(scanned=scanned, insert=len(actions), skip=skip, actions=tuple(actions))


def apply_plan(conn, plan: CopyPlan) -> int:
    """Insert planned events on an open connection. Idempotent on source_ref."""

    written = 0
    for fields in plan.actions:
        existing = conn.execute(
            "SELECT event_id FROM gab_consent_events WHERE source_ref = %s",
            (fields["source_ref"],),
        ).fetchone()
        if existing is not None:
            continue
        tip = conn.execute("SELECT entry_hash FROM gab_consent_events ORDER BY seq DESC LIMIT 1").fetchone()
        prev = None if tip is None else tip[0]
        sealed = seal_event(prev, fields)
        conn.execute(
            """
            INSERT INTO gab_consent_events (
              event_id, principal_id, purpose, granted, text_version, text_sha256, at, source_ref, prev_hash, entry_hash
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                sealed["event_id"],
                sealed["principal_id"],
                sealed["purpose"],
                sealed["granted"],
                sealed["text_version"],
                sealed["text_sha256"],
                sealed["at"],
                sealed["source_ref"] or None,
                sealed["prev_hash"],
                sealed["entry_hash"],
            ),
        )
        written += 1
    return written


def run(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    print(ROLLBACK_NOTE)
    if not args.execute:
        print("dry-run: no database connection")
        return 0
    errors = gate_errors(args)
    if errors:
        print("refused: " + "; ".join(errors))
        return 2
    import psycopg

    with psycopg.connect(args.database_url) as conn:
        with conn.transaction():
            devices = [
                {"device_id": row[0], "principal_id": row[1], "consent_at": row[2]}
                for row in conn.execute(
                    "SELECT device_id, principal_id, consent_at FROM gab_push_devices WHERE consent_at IS NOT NULL"
                ).fetchall()
            ]
            refs = [row[0] for row in conn.execute("SELECT source_ref FROM gab_consent_events WHERE source_ref IS NOT NULL").fetchall()]
            plan = plan_rows(devices, refs, event_id_for=lambda device_id: "cns_push_" + device_id)
            written = apply_plan(conn, plan)
    print(f"scanned={plan.scanned} insert={plan.insert} skip={plan.skip} written={written}")
    return 0
