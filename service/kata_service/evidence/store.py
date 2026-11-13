# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Key cache, nonce window, and evidence rows.

Postgres is the service store. Memory is the stand-in for tests that do not
open a database. There is no Redis.
"""

from __future__ import annotations

import json
import re
import threading
from datetime import datetime
from typing import Any, Protocol

from kata_service.evidence.schema import parse_evidence

_SCHEMA = re.compile(r"^[a-z_][a-z0-9_]*$")


def _stamp(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


class EvidenceStore(Protocol):
    def read_keys(self, directory_hash: str, now: datetime) -> list[dict[str, Any]]: ...

    def put_keys(
        self,
        directory_hash: str,
        keys: list[dict[str, Any]],
        *,
        now: datetime,
        expires_at: datetime,
        max_entries: int,
    ) -> None: ...

    def consume_nonce(self, issuer: str, nonce: str, *, now: datetime, expires_at: datetime) -> bool: ...

    def save_evidence(self, record: dict[str, Any]) -> None: ...

    def list_evidence(self, decision_ref: str | None = None) -> list[dict[str, Any]]: ...

    def link_audit(self, evidence_id: str, audit_id: str) -> None: ...


class MemoryEvidenceStore:
    """Process-local store. Tests use it when they do not have Postgres."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.keys: list[dict[str, Any]] = []
        self.nonces: dict[tuple[str, str], datetime] = {}
        self.evidence: list[dict[str, Any]] = []

    def read_keys(self, directory_hash: str, now: datetime) -> list[dict[str, Any]]:
        with self._lock:
            return [
                {"kid": item["kid"], "jwk": dict(item["jwk"])}
                for item in self.keys
                if item["directory_hash"] == directory_hash and item["expires_at"] > now
            ]

    def put_keys(
        self,
        directory_hash: str,
        keys: list[dict[str, Any]],
        *,
        now: datetime,
        expires_at: datetime,
        max_entries: int,
    ) -> None:
        with self._lock:
            self.keys = [item for item in self.keys if item["directory_hash"] != directory_hash]
            for item in keys:
                self.keys.append(
                    {
                        "directory_hash": directory_hash,
                        "kid": item["kid"],
                        "jwk": dict(item["jwk"]),
                        "fetched_at": now,
                        "expires_at": expires_at,
                    }
                )
            if len(self.keys) > max_entries:
                self.keys.sort(key=lambda item: (item["fetched_at"], item["directory_hash"], item["kid"]))
                self.keys = self.keys[-max_entries:]

    def consume_nonce(self, issuer: str, nonce: str, *, now: datetime, expires_at: datetime) -> bool:
        with self._lock:
            self.nonces = {key: expiry for key, expiry in self.nonces.items() if expiry > now}
            key = (issuer, nonce)
            if key in self.nonces:
                return False
            self.nonces[key] = expires_at
            return True

    def save_evidence(self, record: dict[str, Any]) -> None:
        parse_evidence(record["evidence"])
        with self._lock:
            self.evidence.append(json.loads(json.dumps(record)))

    def list_evidence(self, decision_ref: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            rows = self.evidence if decision_ref is None else [item for item in self.evidence if item["decision_ref"] == decision_ref]
            return json.loads(json.dumps(rows))

    def link_audit(self, evidence_id: str, audit_id: str) -> None:
        with self._lock:
            for item in self.evidence:
                if item["evidence_id"] == evidence_id:
                    item["audit_id"] = audit_id
                    return


class PostgresEvidenceStore:
    """Postgres store. The caller applies the pending migration before use."""

    def __init__(self, database_url: str, *, schema: str = "public") -> None:
        if _SCHEMA.match(schema) is None:
            raise ValueError("schema name is not allowed")
        self.database_url = database_url
        self.schema = schema

    def _connect(self):
        import psycopg

        conn = psycopg.connect(self.database_url)
        conn.execute(f"SET search_path TO {self.schema}")
        return conn

    def read_keys(self, directory_hash: str, now: datetime) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT kid, public_jwk FROM gab_evidence_keys
                WHERE directory_hash = %s AND expires_at > %s
                """,
                (directory_hash, _stamp(now)),
            ).fetchall()
        return [{"kid": row[0], "jwk": json.loads(row[1])} for row in rows]

    def put_keys(
        self,
        directory_hash: str,
        keys: list[dict[str, Any]],
        *,
        now: datetime,
        expires_at: datetime,
        max_entries: int,
    ) -> None:
        fetched = _stamp(now)
        expiry = _stamp(expires_at)
        with self._connect() as conn:
            with conn.transaction():
                conn.execute("DELETE FROM gab_evidence_keys WHERE directory_hash = %s", (directory_hash,))
                for item in keys:
                    conn.execute(
                        """
                        INSERT INTO gab_evidence_keys (directory_hash, kid, public_jwk, fetched_at, expires_at)
                        VALUES (%s, %s, %s, %s, %s)
                        """,
                        (directory_hash, item["kid"], json.dumps(item["jwk"], separators=(",", ":"), sort_keys=True), fetched, expiry),
                    )
                conn.execute(
                    """
                    DELETE FROM gab_evidence_keys
                    WHERE (directory_hash, kid) IN (
                      SELECT directory_hash, kid FROM gab_evidence_keys
                      ORDER BY fetched_at DESC, directory_hash DESC, kid DESC
                      OFFSET %s
                    )
                    """,
                    (max_entries,),
                )

    def consume_nonce(self, issuer: str, nonce: str, *, now: datetime, expires_at: datetime) -> bool:
        with self._connect() as conn:
            with conn.transaction():
                conn.execute("DELETE FROM gab_evidence_nonces WHERE expires_at <= %s", (_stamp(now),))
                row = conn.execute(
                    """
                    INSERT INTO gab_evidence_nonces (issuer, nonce, seen_at, expires_at)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (issuer, nonce) DO NOTHING
                    RETURNING issuer
                    """,
                    (issuer, nonce, _stamp(now), _stamp(expires_at)),
                ).fetchone()
        return row is not None

    def save_evidence(self, record: dict[str, Any]) -> None:
        evidence = parse_evidence(record["evidence"])
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO gab_external_evidence (
                  evidence_id, source, issuer, subject, claims, verified_at, key_id, result, reason,
                  payload_hash, decision_ref, agent_id, agreement_id, action_id, kata_decision, audit_id, created_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    record["evidence_id"],
                    evidence["source"],
                    evidence["issuer"],
                    evidence["subject"],
                    json.dumps(evidence["claims"], separators=(",", ":"), sort_keys=True),
                    evidence["verified_at"],
                    evidence["key_id"],
                    evidence["result"],
                    evidence["reason"],
                    evidence["payload_hash"],
                    record["decision_ref"],
                    record.get("agent_id"),
                    record.get("agreement_id"),
                    record.get("action_id"),
                    record.get("kata_decision"),
                    record.get("audit_id"),
                    record["created_at"],
                ),
            )
            conn.commit()

    def list_evidence(self, decision_ref: str | None = None) -> list[dict[str, Any]]:
        sql = """
            SELECT evidence_id, source, issuer, subject, claims, verified_at, key_id, result, reason,
                   payload_hash, decision_ref, agent_id, agreement_id, action_id, kata_decision, audit_id, created_at
            FROM gab_external_evidence
        """
        params: tuple = ()
        if decision_ref is not None:
            sql += " WHERE decision_ref = %s"
            params = (decision_ref,)
        sql += " ORDER BY created_at, evidence_id"
        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [_evidence_row(row) for row in rows]

    def link_audit(self, evidence_id: str, audit_id: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE gab_external_evidence SET audit_id = %s WHERE evidence_id = %s",
                (audit_id, evidence_id),
            )
            conn.commit()


def _evidence_row(row) -> dict[str, Any]:
    evidence = parse_evidence(
        {
            "source": row[1],
            "issuer": row[2],
            "subject": row[3],
            "claims": json.loads(row[4]),
            "verified_at": row[5],
            "key_id": row[6],
            "result": row[7],
            "reason": row[8],
            "payload_hash": row[9],
        }
    )
    return {
        "evidence_id": row[0],
        "evidence": evidence,
        "decision_ref": row[10],
        "agent_id": row[11],
        "agreement_id": row[12],
        "action_id": row[13],
        "kata_decision": row[14],
        "audit_id": row[15],
        "created_at": row[16],
    }
