# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Offline backfill of keyed email identifiers.

Ship this unexecuted. It does not run on import, on service startup, or in tests
unless a test calls it with an injected connection. Default mode is dry-run and
does not open a database.

Rollback: restore the verified backup named by --backup-confirmed-id. This
script does not drop email, email_hash, or the new columns. Turning
GAB_KEYED_IDENTIFIERS off leaves legacy lookups working unless --strip-plaintext
cleared email. A strip is reversible only by restoring that backup.

Do not point this at a database you have not snapshotted. Do not print row
contents. This is not a compliance claim or a certification.
"""

from __future__ import annotations

import argparse
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable

BACKUP_PHRASE = "BACKUP-VERIFIED"
ROLLBACK_NOTE = (
    "Rollback: restore the verified backup passed as --backup-confirmed-id. "
    "This script does not drop email, email_hash, or the keyed columns. "
    "Turn GAB_KEYED_IDENTIFIERS off to keep legacy lookups. "
    "If --strip-plaintext ran, only that backup restores the cleared addresses. "
    "Do not delete rows as a rollback."
)
_STAMP = re.compile(r"^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}(:\d{2})?Z)?$")
_TABLES = ("gab_logins", "gab_org_logins")


@dataclass(frozen=True)
class BackfillArgs:
    execute: bool
    approve: bool
    backup_id: str
    backup_at: str
    backup_phrase: str
    strip_plaintext: bool
    database_url: str


@dataclass(frozen=True)
class BackfillPlan:
    scanned: int
    update: int
    skip: int
    unreadable: int
    actions: tuple[dict[str, str], ...]


def parse_args(argv: list[str] | None = None) -> BackfillArgs:
    parser = argparse.ArgumentParser(description="Backfill keyed email identifiers. Dry-run unless --execute.")
    parser.add_argument("--execute", action="store_true", help="Write. Requires backup confirmation and --approve.")
    parser.add_argument("--approve", action="store_true", help="Operator approval for a write.")
    parser.add_argument("--backup-confirmed-id", default="", help="Id of a verified backup or snapshot.")
    parser.add_argument("--backup-confirmed-at", default="", help="When that backup was verified, YYYY-MM-DD or UTC timestamp.")
    parser.add_argument("--backup-phrase", default="", help=f"Must be exactly {BACKUP_PHRASE} for a write.")
    parser.add_argument("--strip-plaintext", action="store_true", help="Clear email after a successful round trip. Still requires a write gate.")
    parser.add_argument("--database-url", default="", help="Postgres URL. Never printed.")
    parsed = parser.parse_args(argv)
    return BackfillArgs(
        execute=parsed.execute,
        approve=parsed.approve,
        backup_id=parsed.backup_confirmed_id.strip(),
        backup_at=parsed.backup_confirmed_at.strip(),
        backup_phrase=parsed.backup_phrase.strip(),
        strip_plaintext=parsed.strip_plaintext,
        database_url=parsed.database_url.strip(),
    )


def gate_errors(args: BackfillArgs) -> list[str]:
    """Problems that refuse a write. Dry-run ignores them and does not connect."""

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


def plan_rows(rows: Iterable[dict[str, Any]], provider, *, strip_plaintext: bool) -> BackfillPlan:
    """Plan updates from already-loaded rows. Does not connect. Idempotent.

    Each row needs table, email_hash, email, subject_id, and optional
    email_hmac / email_ciphertext. Addresses in the rows are not copied into
    the returned actions.
    """

    scanned = update = skip = unreadable = 0
    actions: list[dict[str, str]] = []
    for row in rows:
        scanned += 1
        table = str(row.get("table") or "")
        if table not in _TABLES:
            unreadable += 1
            continue
        subject_id = str(row.get("subject_id") or "")
        digest = str(row.get("email_hash") or "")
        stored_email = str(row.get("email") or "")
        email = stored_email.strip().lower()
        if not email and row.get("email_ciphertext") and subject_id:
            try:
                email = provider.unseal(row["email_ciphertext"], subject_id=subject_id).decode("utf-8").strip().lower()
            except Exception:
                email = ""
        if not email or not subject_id or not digest:
            unreadable += 1
            continue
        try:
            token = provider.hmac(email, purpose="identifier")
            sealed = provider.seal(email.encode("utf-8"), subject_id=subject_id)
            opened = provider.unseal(sealed, subject_id=subject_id).decode("utf-8")
        except Exception:
            unreadable += 1
            continue
        if opened != email:
            unreadable += 1
            continue
        already = row.get("email_hmac") == token.encode() and _ciphertext_matches(provider, row, subject_id, email)
        plaintext_done = (not strip_plaintext) or stored_email == ""
        if already and plaintext_done:
            skip += 1
            continue
        stored_email = "" if strip_plaintext else email
        actions.append(
            {
                "table": table,
                "email_hash": digest,
                "email": stored_email,
                "email_hmac": token.encode(),
                "email_kid": token.kid,
                "email_ciphertext": sealed,
            }
        )
        update += 1
    return BackfillPlan(scanned, update, skip, unreadable, tuple(actions))


def apply_plan(connection, plan: BackfillPlan) -> int:
    """Write a plan. The caller owns the transaction. Returns rows written."""

    written = 0
    for action in plan.actions:
        table = action["table"]
        if table not in _TABLES:
            continue
        connection.execute(
            f"""
            UPDATE {table}
            SET email = %s, email_hmac = %s, email_kid = %s, email_ciphertext = %s
            WHERE email_hash = %s
              AND (
                email_hmac IS DISTINCT FROM %s
                OR email_ciphertext IS DISTINCT FROM %s
                OR email IS DISTINCT FROM %s
              )
            """,
            (
                action["email"],
                action["email_hmac"],
                action["email_kid"],
                action["email_ciphertext"],
                action["email_hash"],
                action["email_hmac"],
                action["email_ciphertext"],
                action["email"],
            ),
        )
        written += 1
    return written


def run(argv: list[str] | None = None, *, connect=None, provider=None) -> int:
    """CLI entry. Dry-run returns 0 and does not call connect."""

    args = parse_args(argv)
    print(ROLLBACK_NOTE)
    if not args.execute:
        print("dry-run: no database connection was opened")
        return 0
    errors = gate_errors(args)
    if errors:
        print("refusing: " + "; ".join(errors))
        return 2
    if provider is None:
        print("refusing: a key provider was not supplied to this process")
        return 2
    if connect is None:
        connect = _connect
    conn = connect(args.database_url)
    plan = None
    try:
        rows = _load(conn)
        plan = plan_rows(rows, provider, strip_plaintext=args.strip_plaintext)
        apply_plan(conn, plan)
        if hasattr(conn, "commit"):
            conn.commit()
    finally:
        close = getattr(conn, "close", None)
        if close is not None:
            close()
    if plan is None:
        return 1
    print(f"scanned={plan.scanned} update={plan.update} skip={plan.skip} unreadable={plan.unreadable}")
    return 0


def _connect(database_url: str):
    import psycopg

    return psycopg.connect(database_url)


def _load(connection) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    login_sql = """
        SELECT email_hash, email, principal_id, email_hmac, email_ciphertext
        FROM gab_logins
    """
    org_sql = """
        SELECT email_hash, email, org_id, email_hmac, email_ciphertext
        FROM gab_org_logins
    """
    for table, sql, subject in (("gab_logins", login_sql, "principal_id"), ("gab_org_logins", org_sql, "org_id")):
        fetched = connection.execute(sql).fetchall()
        for item in fetched:
            rows.append(
                {
                    "table": table,
                    "email_hash": item[0],
                    "email": item[1],
                    "subject_id": item[2],
                    subject: item[2],
                    "email_hmac": item[3],
                    "email_ciphertext": item[4],
                }
            )
    return rows


def _ciphertext_matches(provider, row: dict[str, Any], subject_id: str, email: str) -> bool:
    current = row.get("email_ciphertext")
    if not current:
        return False
    try:
        return provider.unseal(current, subject_id=subject_id).decode("utf-8") == email
    except Exception:
        return False
