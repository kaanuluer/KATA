# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Read-only ledger body audit. Ship this unexecuted.

Dry-run does not open a database. A read needs --execute, --approve, a verified
backup id, a verified backup time, and the phrase BACKUP-VERIFIED, because the
script would otherwise connect to whatever URL it is given.

The script prints counts only. It does not print entry bodies.

Rollback: this script does not write. Do not edit or delete ledger rows. A
correction is a new entry. Restoring a backup is only needed if something else
changed the database.

This is not a compliance claim or a certification.
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable

from kata_service.ledger import allowed_field

BACKUP_PHRASE = "BACKUP-VERIFIED"
ROLLBACK_NOTE = (
    "Rollback: this script does not write. Do not edit or delete ledger rows. "
    "A correction is a new append. Restore a backup only if some other change wrote data."
)
_STAMP = re.compile(r"^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}(:\d{2})?Z)?$")


@dataclass(frozen=True)
class AuditArgs:
    execute: bool
    approve: bool
    backup_id: str
    backup_at: str
    backup_phrase: str
    database_url: str


@dataclass(frozen=True)
class AuditCounts:
    scanned: int
    clean: int
    flagged: int


def parse_args(argv: list[str] | None = None) -> AuditArgs:
    parser = argparse.ArgumentParser(description="Read ledger bodies and count fields outside the allow-list.")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--approve", action="store_true")
    parser.add_argument("--backup-confirmed-id", default="")
    parser.add_argument("--backup-confirmed-at", default="")
    parser.add_argument("--backup-phrase", default="")
    parser.add_argument("--database-url", default="")
    parsed = parser.parse_args(argv)
    return AuditArgs(
        execute=parsed.execute,
        approve=parsed.approve,
        backup_id=parsed.backup_confirmed_id.strip(),
        backup_at=parsed.backup_confirmed_at.strip(),
        backup_phrase=parsed.backup_phrase.strip(),
        database_url=parsed.database_url.strip(),
    )


def gate_errors(args: AuditArgs) -> list[str]:
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


def count_documents(documents: Iterable[str]) -> AuditCounts:
    scanned = clean = flagged = 0
    for text in documents:
        scanned += 1
        try:
            document = json.loads(text)
        except json.JSONDecodeError:
            flagged += 1
            continue
        body = document.get("body") if isinstance(document, dict) else None
        if not isinstance(body, dict) or any(not allowed_field(key) or isinstance(value, (dict, list)) for key, value in body.items()):
            flagged += 1
        else:
            clean += 1
    return AuditCounts(scanned, clean, flagged)


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
        rows = conn.execute("SELECT document FROM kata_log_entries ORDER BY sequence").fetchall()
    counts = count_documents(row[0] for row in rows)
    print(f"scanned={counts.scanned} clean={counts.clean} flagged={counts.flagged}")
    return 0
