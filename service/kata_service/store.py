# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: Apache-2.0
"""Storage behind the deployment service.

``MemoryStore`` is for tests. ``PostgresStore`` uses the Neon connection string
Vercel injects as ``DATABASE_URL``. Documents are stored as canonical JSON text
so a later read hashes the same way.
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Protocol

from kata_intent.canonical import canonical_bytes
from kata_intent.keys import PrivateKey
from kata_intent.revocation import TransparencyLog

SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS kata_revocations (
      revocation_id TEXT PRIMARY KEY,
      document TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS kata_log_entries (
      sequence INTEGER PRIMARY KEY,
      document TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS kata_tree_head (
      singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
      document TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS kata_fx_rates (
      currency TEXT NOT NULL,
      reference_currency TEXT NOT NULL,
      day TEXT NOT NULL,
      rate TEXT NOT NULL,
      PRIMARY KEY (currency, reference_currency, day)
    )
    """,
)

_LOCK_KEY = 8412552


class Store(Protocol):
    def list_revocations(self) -> list[dict[str, Any]]: ...

    def revocation_exists(self, revocation_id: str) -> bool: ...

    def put_revocation(self, revocation_id: str, document: dict[str, Any]) -> None: ...

    def record_revocation(
        self, revocation_id: str, document: dict[str, Any], private_key: PrivateKey, at: datetime
    ) -> dict[str, Any] | None: ...

    def append_and_sign(
        self, kind: str, body: dict[str, Any], private_key: PrivateKey, at: datetime
    ) -> tuple[dict[str, Any], dict[str, Any]]: ...

    def get_entry(self, sequence: int) -> dict[str, Any] | None: ...

    def snapshot(self) -> tuple[list[dict[str, Any]], dict[str, Any] | None]: ...

    def get_fx(self, currency: str, reference_currency: str, day: str) -> str | None: ...

    def put_fx(self, currency: str, reference_currency: str, day: str, rate: str) -> None: ...


def dump_doc(document: dict[str, Any]) -> str:
    return canonical_bytes(document).decode("utf-8")


def load_doc(text: str) -> dict[str, Any]:
    loaded = json.loads(text, parse_float=Decimal)
    if not isinstance(loaded, dict):
        raise ValueError("stored document is not an object")
    return loaded


class MemoryStore:
    """Process-local store. Tests use this. It is not the Vercel deployment store."""

    def __init__(self) -> None:
        self._revocations: dict[str, dict[str, Any]] = {}
        self._entries: list[dict[str, Any]] = []
        self._head: dict[str, Any] | None = None
        self._fx: dict[tuple[str, str, str], str] = {}
        self._lock = threading.Lock()

    def list_revocations(self) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(item) for item in self._revocations.values()]

    def revocation_exists(self, revocation_id: str) -> bool:
        with self._lock:
            return revocation_id in self._revocations

    def put_revocation(self, revocation_id: str, document: dict[str, Any]) -> None:
        with self._lock:
            self._revocations[revocation_id] = dict(document)

    def record_revocation(
        self, revocation_id: str, document: dict[str, Any], private_key: PrivateKey, at: datetime
    ) -> dict[str, Any] | None:
        with self._lock:
            if revocation_id in self._revocations:
                return None
            log = _log_from(self._entries)
            record = log.append("revocation", document)
            head = log.sign_tree_head(private_key, at)
            self._entries.append(record)
            self._head = head
            self._revocations[revocation_id] = dict(document)
            return record

    def append_and_sign(
        self, kind: str, body: dict[str, Any], private_key: PrivateKey, at: datetime
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        with self._lock:
            log = _log_from(self._entries)
            record = log.append(kind, body)
            head = log.sign_tree_head(private_key, at)
            self._entries.append(record)
            self._head = head
            return record, head

    def get_entry(self, sequence: int) -> dict[str, Any] | None:
        with self._lock:
            if sequence < 1 or sequence > len(self._entries):
                return None
            return self._entries[sequence - 1]

    def snapshot(self) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
        with self._lock:
            return list(self._entries), self._head

    def get_fx(self, currency: str, reference_currency: str, day: str) -> str | None:
        with self._lock:
            return self._fx.get((currency, reference_currency, day))

    def put_fx(self, currency: str, reference_currency: str, day: str, rate: str) -> None:
        with self._lock:
            self._fx[(currency, reference_currency, day)] = rate


class PostgresStore:
    """Neon Postgres. The connection string comes from the Vercel integration."""

    def __init__(self, database_url: str, schema_url: str | None = None):
        self.database_url = database_url
        self.schema_url = schema_url or database_url
        self._ready = False
        self._schema_lock = threading.Lock()

    def list_revocations(self) -> list[dict[str, Any]]:
        self._ensure()
        with self._connect() as conn:
            rows = conn.execute("SELECT document FROM kata_revocations ORDER BY revocation_id").fetchall()
        return [load_doc(row[0]) for row in rows]

    def revocation_exists(self, revocation_id: str) -> bool:
        self._ensure()
        with self._connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM kata_revocations WHERE revocation_id = %s", (revocation_id,)
            ).fetchone()
        return row is not None

    def put_revocation(self, revocation_id: str, document: dict[str, Any]) -> None:
        self._ensure()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO kata_revocations (revocation_id, document)
                VALUES (%s, %s)
                ON CONFLICT (revocation_id) DO NOTHING
                """,
                (revocation_id, dump_doc(document)),
            )

    def record_revocation(
        self, revocation_id: str, document: dict[str, Any], private_key: PrivateKey, at: datetime
    ) -> dict[str, Any] | None:
        self._ensure()
        with self._connect() as conn:
            with conn.transaction():
                conn.execute("SELECT pg_advisory_xact_lock(%s)", (_LOCK_KEY,))
                existing = conn.execute(
                    "SELECT 1 FROM kata_revocations WHERE revocation_id = %s", (revocation_id,)
                ).fetchone()
                if existing is not None:
                    return None
                rows = conn.execute("SELECT document FROM kata_log_entries ORDER BY sequence").fetchall()
                log = _log_from([load_doc(row[0]) for row in rows])
                record = log.append("revocation", document)
                head = log.sign_tree_head(private_key, at)
                conn.execute(
                    "INSERT INTO kata_log_entries (sequence, document) VALUES (%s, %s)",
                    (record["sequence"], dump_doc(record)),
                )
                conn.execute(
                    """
                    INSERT INTO kata_tree_head (singleton, document) VALUES (1, %s)
                    ON CONFLICT (singleton) DO UPDATE SET document = EXCLUDED.document
                    """,
                    (dump_doc(head),),
                )
                conn.execute(
                    "INSERT INTO kata_revocations (revocation_id, document) VALUES (%s, %s)",
                    (revocation_id, dump_doc(document)),
                )
        return record

    def append_and_sign(
        self, kind: str, body: dict[str, Any], private_key: PrivateKey, at: datetime
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        self._ensure()
        with self._connect() as conn:
            with conn.transaction():
                conn.execute("SELECT pg_advisory_xact_lock(%s)", (_LOCK_KEY,))
                rows = conn.execute("SELECT document FROM kata_log_entries ORDER BY sequence").fetchall()
                log = _log_from([load_doc(row[0]) for row in rows])
                record = log.append(kind, body)
                head = log.sign_tree_head(private_key, at)
                conn.execute(
                    "INSERT INTO kata_log_entries (sequence, document) VALUES (%s, %s)",
                    (record["sequence"], dump_doc(record)),
                )
                conn.execute(
                    """
                    INSERT INTO kata_tree_head (singleton, document) VALUES (1, %s)
                    ON CONFLICT (singleton) DO UPDATE SET document = EXCLUDED.document
                    """,
                    (dump_doc(head),),
                )
        return record, head

    def get_entry(self, sequence: int) -> dict[str, Any] | None:
        self._ensure()
        with self._connect() as conn:
            row = conn.execute(
                "SELECT document FROM kata_log_entries WHERE sequence = %s", (sequence,)
            ).fetchone()
        if row is None:
            return None
        return load_doc(row[0])

    def snapshot(self) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
        self._ensure()
        with self._connect() as conn:
            rows = conn.execute("SELECT document FROM kata_log_entries ORDER BY sequence").fetchall()
            head_row = conn.execute("SELECT document FROM kata_tree_head WHERE singleton = 1").fetchone()
        head = load_doc(head_row[0]) if head_row else None
        return [load_doc(row[0]) for row in rows], head

    def get_fx(self, currency: str, reference_currency: str, day: str) -> str | None:
        self._ensure()
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT rate FROM kata_fx_rates
                WHERE currency = %s AND reference_currency = %s AND day = %s
                """,
                (currency, reference_currency, day),
            ).fetchone()
        return None if row is None else str(row[0])

    def put_fx(self, currency: str, reference_currency: str, day: str, rate: str) -> None:
        self._ensure()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO kata_fx_rates (currency, reference_currency, day, rate)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (currency, reference_currency, day) DO UPDATE SET rate = EXCLUDED.rate
                """,
                (currency, reference_currency, day, rate),
            )

    def _ensure(self) -> None:
        if self._ready:
            return
        with self._schema_lock:
            if self._ready:
                return
            import psycopg

            with psycopg.connect(self.schema_url, autocommit=True) as conn:
                for statement in SCHEMA:
                    conn.execute(statement)
            self._ready = True

    def _connect(self):
        from kata_service.db_pool import connection

        return connection(self.database_url)


def open_store(database_url: str | None, schema_url: str | None = None) -> PostgresStore:
    if not database_url:
        raise RuntimeError("DATABASE_URL is not set")
    return PostgresStore(database_url, schema_url)


def _log_from(entries: list[dict[str, Any]]) -> TransparencyLog:
    log = TransparencyLog()
    log.entries = list(entries)
    return log


def utcnow() -> datetime:
    return datetime.now(timezone.utc)
