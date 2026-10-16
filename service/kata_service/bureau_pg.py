# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Postgres repository for the bureau. Uses DATABASE_URL (Neon on Vercel)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from kata_service.bureau import BureauError, email_hash, in_test_mode
from kata_service.store import dump_doc, load_doc

_MIGRATIONS = Path(__file__).resolve().parent / "migrations"
_MIGRATION = _MIGRATIONS / "001_bureau.sql"


def migration_sql() -> str:
    return "\n".join(path.read_text(encoding="utf-8") for path in sorted(_MIGRATIONS.glob("*.sql")))


def migration_statements() -> list[str]:
    statements = []
    for chunk in migration_sql().split(";"):
        lines = [line for line in chunk.splitlines() if not line.strip().startswith("--")]
        text = "\n".join(lines).strip()
        if text:
            statements.append(text)
    return statements


class PostgresRepo:
    def __init__(self, database_url: str, schema_url: str | None = None) -> None:
        self.database_url = database_url
        self.schema_url = schema_url or database_url
        self._ready = False

    def migration_versions(self) -> list[str]:
        self._ensure()
        with self._connect() as conn:
            rows = conn.execute("SELECT version FROM gab_schema_migrations ORDER BY version").fetchall()
        return [row[0] for row in rows]

    def create_org(self, record: dict[str, Any]) -> None:
        self._execute(
            "INSERT INTO gab_organizations (org_id, name, org_type, status, created_at) VALUES (%s, %s, %s, %s, %s)",
            (record["org_id"], record["name"], record["org_type"], record["status"], record["created_at"]),
        )

    def set_org_created_at(self, org_id: str, created_at: str) -> None:
        self._execute("UPDATE gab_organizations SET created_at = %s WHERE org_id = %s", (created_at, org_id))

    def get_org(self, org_id: str) -> dict[str, Any] | None:
        row = self._one("SELECT org_id, name, org_type, status, created_at FROM gab_organizations WHERE org_id = %s", (org_id,))
        if row is None:
            return None
        return {"org_id": row[0], "name": row[1], "org_type": row[2], "status": row[3], "created_at": row[4]}

    def create_key(self, record: dict[str, Any]) -> None:
        self._execute(
            """
            INSERT INTO gab_api_keys (
              key_id, org_id, name, prefix, secret_hash, scopes, created_at, revoked_at, rotated_from, environment
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                record["key_id"],
                record["org_id"],
                record["name"],
                record["prefix"],
                record["secret_hash"],
                json.dumps(list(record["scopes"])),
                record["created_at"],
                record.get("revoked_at"),
                record.get("rotated_from"),
                "test" if record.get("environment") == "test" or str(record.get("prefix") or "").startswith("gab_test_") else "live",
            ),
        )

    def key_by_hash(self, secret_hash: str) -> dict[str, Any] | None:
        row = self._one("SELECT key_id FROM gab_api_keys WHERE secret_hash = %s", (secret_hash,))
        if row is None:
            return None
        return self.get_key(row[0])

    def get_key(self, key_id: str) -> dict[str, Any] | None:
        row = self._one(
            """
            SELECT key_id, org_id, name, prefix, secret_hash, scopes, created_at, revoked_at, rotated_from, environment
            FROM gab_api_keys WHERE key_id = %s
            """,
            (key_id,),
        )
        if row is None:
            return None
        return _key_row(row)

    def list_keys(self, org_id: str) -> list[dict[str, Any]]:
        rows = self._all(
            """
            SELECT key_id, org_id, name, prefix, secret_hash, scopes, created_at, revoked_at, rotated_from, environment
            FROM gab_api_keys WHERE org_id = %s ORDER BY created_at
            """,
            (org_id,),
        )
        return [_key_row(row) for row in rows]

    def revoke_key(self, key_id: str, at: str) -> None:
        self._execute("UPDATE gab_api_keys SET revoked_at = %s WHERE key_id = %s", (at, key_id))

    def add_audit(self, record: dict[str, Any]) -> None:
        self._execute(
            """
            INSERT INTO gab_audit (audit_id, at, org_id, key_id, method, path, status, purpose_code, agent_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                record["audit_id"],
                record["at"],
                record.get("org_id"),
                record.get("key_id"),
                record["method"],
                record["path"],
                record["status"],
                record.get("purpose_code"),
                record.get("agent_id"),
            ),
        )

    def list_audit(self, org_id: str | None) -> list[dict[str, Any]]:
        if org_id is None:
            rows = self._all(
                "SELECT audit_id, at, org_id, key_id, method, path, status, purpose_code, agent_id FROM gab_audit ORDER BY at",
                (),
            )
        else:
            rows = self._all(
                """
                SELECT audit_id, at, org_id, key_id, method, path, status, purpose_code, agent_id
                FROM gab_audit WHERE org_id = %s ORDER BY at
                """,
                (org_id,),
            )
        return [
            {
                "audit_id": row[0],
                "at": row[1],
                "org_id": row[2],
                "key_id": row[3],
                "method": row[4],
                "path": row[5],
                "status": row[6],
                "purpose_code": row[7],
                "agent_id": row[8],
            }
            for row in rows
        ]

    def hit_rate(self, subject: str, window: str) -> int:
        self._ensure()
        with self._connect() as conn:
            row = conn.execute(
                """
                INSERT INTO gab_rate (subject, window_start, hits) VALUES (%s, %s, 1)
                ON CONFLICT (subject, window_start) DO UPDATE SET hits = gab_rate.hits + 1
                RETURNING hits
                """,
                (subject, window),
            ).fetchone()
        return int(row[0])

    def ensure_principal(self, principal_id: str, at: str) -> None:
        self._execute(
            "INSERT INTO gab_principals (principal_id, created_at) VALUES (%s, %s) ON CONFLICT (principal_id) DO NOTHING",
            (principal_id, at),
        )

    def insert_login(self, email: str, principal_id: str, at: str) -> str:
        """Bind an email once. A conflict leaves the existing principal in place."""

        digest = email_hash(email)
        row = self._one(
            """
            INSERT INTO gab_logins (email_hash, email, principal_id, created_at) VALUES (%s, %s, %s, %s)
            ON CONFLICT (email_hash) DO NOTHING
            RETURNING principal_id
            """,
            (digest, email.strip().lower(), principal_id, at),
        )
        if row is not None:
            return "inserted"
        current = self.login_by_hash(digest)
        if current is not None and current["principal_id"] == principal_id:
            return "same"
        return "conflict"

    def upsert_login(self, email: str, principal_id: str, at: str) -> None:
        self.insert_login(email, principal_id, at)

    def login_by_email(self, email: str) -> dict[str, Any] | None:
        return self.login_by_hash(email_hash(email))

    def login_by_hash(self, digest: str) -> dict[str, Any] | None:
        row = self._one("SELECT email, principal_id, created_at FROM gab_logins WHERE email_hash = %s", (digest,))
        if row is None:
            return None
        return {"email": row[0], "principal_id": row[1], "created_at": row[2]}

    def upsert_org_login(self, email: str, org_id: str, at: str) -> None:
        digest = email_hash(email)
        self._execute(
            """
            INSERT INTO gab_org_logins (email_hash, email, org_id, created_at) VALUES (%s, %s, %s, %s)
            ON CONFLICT (email_hash) DO UPDATE SET org_id = EXCLUDED.org_id
            """,
            (digest, email.strip().lower(), org_id, at),
        )

    def org_login_by_email(self, email: str) -> dict[str, Any] | None:
        return self.org_login_by_hash(email_hash(email))

    def org_login_by_hash(self, digest: str) -> dict[str, Any] | None:
        row = self._one("SELECT email, org_id, created_at FROM gab_org_logins WHERE email_hash = %s", (digest,))
        if row is None:
            return None
        return {"email": row[0], "org_id": row[1], "created_at": row[2]}

    def put_magic(self, record: dict[str, Any]) -> None:
        self._execute(
            """
            INSERT INTO gab_magic_links (token_hash, kind, subject_hash, expires_at, used_at)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (record["token_hash"], record["kind"], record["subject_hash"], record["expires_at"], record.get("used_at")),
        )

    def get_magic(self, token_hash_value: str) -> dict[str, Any] | None:
        row = self._one(
            "SELECT token_hash, kind, subject_hash, expires_at, used_at FROM gab_magic_links WHERE token_hash = %s",
            (token_hash_value,),
        )
        if row is None:
            return None
        return {"token_hash": row[0], "kind": row[1], "subject_hash": row[2], "expires_at": row[3], "used_at": row[4]}

    def consume_magic(self, token_hash_value: str, at: str) -> None:
        self._execute("UPDATE gab_magic_links SET used_at = %s WHERE token_hash = %s", (at, token_hash_value))

    def put_session(self, record: dict[str, Any]) -> None:
        self._execute(
            "INSERT INTO gab_sessions (token_hash, kind, subject_id, expires_at) VALUES (%s, %s, %s, %s)",
            (record["token_hash"], record["kind"], record["subject_id"], record["expires_at"]),
        )

    def get_session(self, token_hash_value: str) -> dict[str, Any] | None:
        row = self._one(
            "SELECT token_hash, kind, subject_id, expires_at FROM gab_sessions WHERE token_hash = %s",
            (token_hash_value,),
        )
        if row is None:
            return None
        return {"token_hash": row[0], "kind": row[1], "subject_id": row[2], "expires_at": row[3]}

    def save_agent(self, record: dict[str, Any]) -> None:
        self._execute(
            """
            INSERT INTO gab_agents (
              agent_id, operator_org_id, principal_id, status, verification_level, algorithm,
              fingerprint, public_key, created_at, updated_at, score, score_reasons, cold_start,
              principal_public_key
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (agent_id) DO UPDATE SET
              status = EXCLUDED.status,
              verification_level = EXCLUDED.verification_level,
              updated_at = EXCLUDED.updated_at,
              score = EXCLUDED.score,
              score_reasons = EXCLUDED.score_reasons,
              cold_start = EXCLUDED.cold_start,
              principal_public_key = EXCLUDED.principal_public_key
            """,
            (
                record["agent_id"],
                record["operator_org_id"],
                record["principal_id"],
                record["status"],
                record["verification_level"],
                record["algorithm"],
                record["fingerprint"],
                json.dumps(record["public_key"]),
                record["created_at"],
                record["updated_at"],
                int(record.get("score") or 0),
                json.dumps(record.get("score_reasons") or []),
                1 if record.get("cold_start", True) else 0,
                json.dumps(record["principal_public_key"]) if record.get("principal_public_key") else None,
            ),
        )

    def get_agent(self, agent_id: str) -> dict[str, Any] | None:
        row = self._one("SELECT * FROM gab_agents WHERE agent_id = %s", (agent_id,))
        return None if row is None else _agent_row(row)

    def agent_by_fingerprint(self, fingerprint: str) -> dict[str, Any] | None:
        row = self._one("SELECT * FROM gab_agents WHERE fingerprint = %s", (fingerprint,))
        return None if row is None else _agent_row(row)

    def list_agents(self, *, operator_org_id: str | None = None, principal_id: str | None = None) -> list[dict[str, Any]]:
        if operator_org_id is not None:
            rows = self._all("SELECT * FROM gab_agents WHERE operator_org_id = %s", (operator_org_id,))
        elif principal_id is not None:
            rows = self._all("SELECT * FROM gab_agents WHERE principal_id = %s", (principal_id,))
        else:
            rows = self._all("SELECT * FROM gab_agents", ())
        return [_agent_row(row) for row in rows]

    def save_agreement(self, record: dict[str, Any]) -> None:
        self._execute(
            """
            INSERT INTO gab_agreements (agreement_id, agent_id, document, status, updated_at)
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (agreement_id) DO UPDATE SET document = EXCLUDED.document, status = EXCLUDED.status, updated_at = EXCLUDED.updated_at
            """,
            (record["agreement_id"], record["agent_id"], dump_doc(record["document"]), record["status"], record["updated_at"]),
        )

    def get_agreement(self, agreement_id: str) -> dict[str, Any] | None:
        row = self._one(
            "SELECT agreement_id, agent_id, document, status, updated_at FROM gab_agreements WHERE agreement_id = %s",
            (agreement_id,),
        )
        return None if row is None else _agreement_row(row)

    def list_agreements(self, agent_id: str) -> list[dict[str, Any]]:
        rows = self._all(
            "SELECT agreement_id, agent_id, document, status, updated_at FROM gab_agreements WHERE agent_id = %s",
            (agent_id,),
        )
        return [_agreement_row(row) for row in rows]

    def add_report(self, record: dict[str, Any]) -> None:
        self._ensure()
        try:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO gab_reports (
                      report_id, agent_id, reporter_org_id, kind, evidence_hash, summary, outcome, created_at, excluded, action_id
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        record["report_id"],
                        record["agent_id"],
                        record["reporter_org_id"],
                        record["kind"],
                        record["evidence_hash"],
                        record["summary"],
                        record.get("outcome"),
                        record["created_at"],
                        1 if record.get("excluded") else 0,
                        record.get("action_id"),
                    ),
                )
        except Exception as exc:
            if "unique" in str(exc).lower() or "duplicate" in str(exc).lower():
                raise BureauError(409, "duplicate report") from exc
            raise

    def reports_for_agent(self, agent_id: str) -> list[dict[str, Any]]:
        rows = self._all(
            """
            SELECT report_id, agent_id, reporter_org_id, kind, evidence_hash, summary, outcome, created_at, excluded, action_id
            FROM gab_reports WHERE agent_id = %s ORDER BY created_at
            """,
            (agent_id,),
        )
        return [_report_row(row) for row in rows]

    def reports_by_org_on_day(self, org_id: str, day: str) -> int:
        row = self._one(
            "SELECT COUNT(*) FROM gab_reports WHERE reporter_org_id = %s AND created_at LIKE %s",
            (org_id, day + "%"),
        )
        return int(row[0] if row else 0)

    def org_has_report(self, org_id: str) -> bool:
        row = self._one("SELECT 1 FROM gab_reports WHERE reporter_org_id = %s LIMIT 1", (org_id,))
        return row is not None

    def get_report(self, report_id: str) -> dict[str, Any] | None:
        row = self._one(
            """
            SELECT report_id, agent_id, reporter_org_id, kind, evidence_hash, summary, outcome, created_at, excluded, action_id
            FROM gab_reports WHERE report_id = %s
            """,
            (report_id,),
        )
        return None if row is None else _report_row(row)

    def set_report_excluded(self, report_id: str, excluded: bool) -> None:
        self._execute("UPDATE gab_reports SET excluded = %s WHERE report_id = %s", (1 if excluded else 0, report_id))

    def all_reports(self) -> list[dict[str, Any]]:
        rows = self._all(
            """
            SELECT report_id, agent_id, reporter_org_id, kind, evidence_hash, summary, outcome, created_at, excluded, action_id
            FROM gab_reports ORDER BY created_at
            """,
            (),
        )
        return [_report_row(row) for row in rows]

    def org_directory(self) -> dict[str, dict[str, str]]:
        rows = self._all("SELECT org_id, org_type, created_at, status FROM gab_organizations", ())
        return {row[0]: {"org_type": row[1], "created_at": row[2], "status": row[3]} for row in rows}

    def add_interaction(self, record: dict[str, Any]) -> None:
        self._execute(
            """
            INSERT INTO gab_interactions (
              interaction_id, agent_id, operator_org_id, counterparty_org_id, action_id, amount, currency, agreement_id, at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                record["interaction_id"],
                record["agent_id"],
                record["operator_org_id"],
                record["counterparty_org_id"],
                record["action_id"],
                record.get("amount"),
                record.get("currency"),
                record.get("agreement_id"),
                record["at"],
            ),
        )

    def interactions_for_agent(self, agent_id: str) -> list[dict[str, Any]]:
        rows = self._all(
            """
            SELECT interaction_id, agent_id, operator_org_id, counterparty_org_id, action_id, amount, currency, agreement_id, at
            FROM gab_interactions WHERE agent_id = %s
            """,
            (agent_id,),
        )
        return [_interaction_row(row) for row in rows]

    def interactions_for_operator(self, operator_org_id: str) -> list[dict[str, Any]]:
        rows = self._all(
            """
            SELECT interaction_id, agent_id, operator_org_id, counterparty_org_id, action_id, amount, currency, agreement_id, at
            FROM gab_interactions WHERE operator_org_id = %s
            """,
            (operator_org_id,),
        )
        return [_interaction_row(row) for row in rows]

    def add_signal(self, record: dict[str, Any]) -> None:
        self._execute(
            """
            INSERT INTO gab_agent_signals (agent_id, kind, value, created_at) VALUES (%s, %s, %s, %s)
            ON CONFLICT (agent_id, kind, value) DO NOTHING
            """,
            (record["agent_id"], record["kind"], record["value"], record["created_at"]),
        )

    def agent_ids_for_signal(self, kind: str, value: str) -> list[str]:
        rows = self._all("SELECT agent_id FROM gab_agent_signals WHERE kind = %s AND value = %s", (kind, value))
        return [row[0] for row in rows]

    def all_interactions(self) -> list[dict[str, Any]]:
        rows = self._all(
            """
            SELECT interaction_id, agent_id, operator_org_id, counterparty_org_id, action_id, amount, currency, agreement_id, at
            FROM gab_interactions
            """
        )
        return [_interaction_row(row) for row in rows]

    def add_org_signal(self, record: dict[str, Any]) -> None:
        self._execute(
            """
            INSERT INTO gab_org_signals (org_id, kind, value, created_at) VALUES (%s, %s, %s, %s)
            ON CONFLICT (org_id, kind, value) DO NOTHING
            """,
            (record["org_id"], record["kind"], record["value"], record["created_at"]),
        )

    def org_signal_groups(self) -> list[set[str]]:
        rows = self._all("SELECT org_id, value FROM gab_org_signals")
        grouped: dict[str, set[str]] = {}
        for org_id, value in rows:
            grouped.setdefault(value, set()).add(org_id)
        return [members for members in grouped.values() if len(members) >= 2]

    def add_identity_link(self, record: dict[str, Any]) -> None:
        self._execute(
            """
            INSERT INTO gab_identity_links (link_id, agent_id, linked_agent_id, signal, created_at)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (record["link_id"], record["agent_id"], record["linked_agent_id"], record["signal"], record["created_at"]),
        )

    def links_for_agent(self, agent_id: str) -> list[dict[str, Any]]:
        rows = self._all(
            "SELECT link_id, agent_id, linked_agent_id, signal, created_at FROM gab_identity_links WHERE agent_id = %s",
            (agent_id,),
        )
        return [
            {
                "link_id": row[0],
                "agent_id": row[1],
                "linked_agent_id": row[2],
                "signal": row[3],
                "created_at": row[4],
            }
            for row in rows
        ]

    def add_proofing(self, record: dict[str, Any]) -> None:
        self._execute(
            """
            INSERT INTO gab_proofings (proofing_id, agent_id, org_id, method, evidence_hash, created_at)
            VALUES (%s, %s, %s, %s, %s, %s)
            ON CONFLICT (agent_id, method, evidence_hash) DO NOTHING
            """,
            (
                record["proofing_id"],
                record["agent_id"],
                record["org_id"],
                record["method"],
                record["evidence_hash"],
                record["created_at"],
            ),
        )

    def proofings_for_agent(self, agent_id: str) -> list[dict[str, Any]]:
        rows = self._all(
            """
            SELECT proofing_id, agent_id, org_id, method, evidence_hash, created_at
            FROM gab_proofings WHERE agent_id = %s ORDER BY created_at
            """,
            (agent_id,),
        )
        return [
            {
                "proofing_id": row[0],
                "agent_id": row[1],
                "org_id": row[2],
                "method": row[3],
                "evidence_hash": row[4],
                "created_at": row[5],
            }
            for row in rows
        ]

    def add_consortium_member(self, record: dict[str, Any]) -> None:
        self._execute(
            """
            INSERT INTO gab_consortium_members (member_id, org_id, status, created_at)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (org_id) DO NOTHING
            """,
            (record["member_id"], record["org_id"], record["status"], record["created_at"]),
        )

    def consortium_member_for_org(self, org_id: str) -> dict[str, Any] | None:
        row = self._one(
            "SELECT member_id, org_id, status, created_at FROM gab_consortium_members WHERE org_id = %s",
            (org_id,),
        )
        if row is None:
            return None
        return {"member_id": row[0], "org_id": row[1], "status": row[2], "created_at": row[3]}

    def add_sighting(self, record: dict[str, Any]) -> dict[str, Any]:
        self._execute(
            """
            INSERT INTO gab_consortium_sightings (sighting_id, member_id, fingerprint, seen_at)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (member_id, fingerprint) DO NOTHING
            """,
            (record["sighting_id"], record["member_id"], record["fingerprint"], record["seen_at"]),
        )
        row = self._one(
            """
            SELECT sighting_id, member_id, fingerprint, seen_at
            FROM gab_consortium_sightings WHERE member_id = %s AND fingerprint = %s
            """,
            (record["member_id"], record["fingerprint"]),
        )
        if row is None:
            raise BureauError(500, "sighting was not stored")
        return {"sighting_id": row[0], "member_id": row[1], "fingerprint": row[2], "seen_at": row[3]}

    def sighting_member_ids(self, fingerprint: str) -> list[str]:
        rows = self._all(
            "SELECT member_id FROM gab_consortium_sightings WHERE fingerprint = %s",
            (fingerprint,),
        )
        return [row[0] for row in rows]

    def add_inquiry(self, record: dict[str, Any]) -> None:
        self._execute(
            """
            INSERT INTO gab_inquiries (inquiry_id, org_id, agent_id, principal_id, purpose_code, at)
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (record["inquiry_id"], record["org_id"], record["agent_id"], record["principal_id"], record["purpose_code"], record["at"]),
        )

    def inquiries_for_principal(self, principal_id: str) -> list[dict[str, Any]]:
        rows = self._all(
            """
            SELECT inquiry_id, org_id, agent_id, principal_id, purpose_code, at
            FROM gab_inquiries WHERE principal_id = %s ORDER BY at
            """,
            (principal_id,),
        )
        return [
            {
                "inquiry_id": row[0],
                "org_id": row[1],
                "agent_id": row[2],
                "principal_id": row[3],
                "purpose_code": row[4],
                "at": row[5],
            }
            for row in rows
        ]

    def add_subscription(self, record: dict[str, Any]) -> None:
        try:
            self._execute(
                """
                INSERT INTO gab_subscriptions (subscription_id, org_id, agent_id, webhook_url, created_at)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (record["subscription_id"], record["org_id"], record["agent_id"], record["webhook_url"], record["created_at"]),
            )
        except Exception as exc:
            if "unique" in str(exc).lower() or "duplicate" in str(exc).lower():
                raise BureauError(409, "subscription already exists") from exc
            raise

    def subscriptions_for_agent(self, agent_id: str) -> list[dict[str, Any]]:
        rows = self._all(
            "SELECT subscription_id, org_id, agent_id, webhook_url, created_at FROM gab_subscriptions WHERE agent_id = %s",
            (agent_id,),
        )
        return [_sub_row(row) for row in rows]

    def subscriptions_for_org(self, org_id: str) -> list[dict[str, Any]]:
        rows = self._all(
            "SELECT subscription_id, org_id, agent_id, webhook_url, created_at FROM gab_subscriptions WHERE org_id = %s",
            (org_id,),
        )
        return [_sub_row(row) for row in rows]

    def get_subscription(self, subscription_id: str) -> dict[str, Any] | None:
        row = self._one(
            "SELECT subscription_id, org_id, agent_id, webhook_url, created_at FROM gab_subscriptions WHERE subscription_id = %s",
            (subscription_id,),
        )
        return None if row is None else _sub_row(row)

    def add_delivery(self, record: dict[str, Any]) -> None:
        self._execute(
            """
            INSERT INTO gab_webhook_deliveries (
              delivery_id, org_id, agent_id, alert_id, attempt, at, outcome, http_status, detail
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                record["delivery_id"],
                record["org_id"],
                record["agent_id"],
                record["alert_id"],
                record["attempt"],
                record["at"],
                record["outcome"],
                record.get("http_status"),
                record["detail"],
            ),
        )

    def deliveries_for_org(self, org_id: str) -> list[dict[str, Any]]:
        rows = self._all(
            """
            SELECT delivery_id, alert_id, agent_id, attempt, at, outcome, http_status, detail
            FROM gab_webhook_deliveries WHERE org_id = %s ORDER BY at, attempt
            """,
            (org_id,),
        )
        return [
            {
                "delivery_id": row[0],
                "org_id": org_id,
                "alert_id": row[1],
                "agent_id": row[2],
                "attempt": row[3],
                "at": row[4],
                "outcome": row[5],
                "http_status": row[6],
                "detail": row[7],
            }
            for row in rows
        ]

    def delete_subscription(self, subscription_id: str, org_id: str) -> bool:
        self._ensure()
        with self._connect() as conn:
            cursor = conn.execute(
                "DELETE FROM gab_subscriptions WHERE subscription_id = %s AND org_id = %s",
                (subscription_id, org_id),
            )
            return cursor.rowcount > 0

    def add_alert(self, record: dict[str, Any]) -> None:
        self._execute(
            """
            INSERT INTO gab_alerts (alert_id, org_id, agent_id, kind, document, created_at, delivered)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            """,
            (
                record["alert_id"],
                record["org_id"],
                record["agent_id"],
                record["kind"],
                dump_doc(record["document"]),
                record["created_at"],
                1 if record.get("delivered") else 0,
            ),
        )

    def alerts_for_org(self, org_id: str) -> list[dict[str, Any]]:
        rows = self._all(
            "SELECT alert_id, org_id, agent_id, kind, document, created_at, delivered FROM gab_alerts WHERE org_id = %s ORDER BY created_at",
            (org_id,),
        )
        return [
            {
                "alert_id": row[0],
                "org_id": row[1],
                "agent_id": row[2],
                "kind": row[3],
                "document": load_doc(row[4]),
                "created_at": row[5],
                "delivered": bool(row[6]),
            }
            for row in rows
        ]

    def add_dispute(self, record: dict[str, Any]) -> None:
        self._execute(
            """
            INSERT INTO gab_disputes (dispute_id, report_id, principal_id, statement, status, outcome, created_at, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                record["dispute_id"],
                record["report_id"],
                record["principal_id"],
                record["statement"],
                record["status"],
                record.get("outcome"),
                record["created_at"],
                record["updated_at"],
            ),
        )

    def list_disputes(self) -> list[dict[str, Any]]:
        rows = self._all(
            "SELECT dispute_id, report_id, principal_id, statement, status, outcome, created_at, updated_at FROM gab_disputes ORDER BY created_at",
            (),
        )
        return [_dispute_row(row) for row in rows]

    def disputes_for_principal(self, principal_id: str) -> list[dict[str, Any]]:
        rows = self._all(
            """
            SELECT dispute_id, report_id, principal_id, statement, status, outcome, created_at, updated_at
            FROM gab_disputes WHERE principal_id = %s ORDER BY created_at
            """,
            (principal_id,),
        )
        return [_dispute_row(row) for row in rows]

    def get_dispute(self, dispute_id: str) -> dict[str, Any] | None:
        row = self._one(
            """
            SELECT dispute_id, report_id, principal_id, statement, status, outcome, created_at, updated_at
            FROM gab_disputes WHERE dispute_id = %s
            """,
            (dispute_id,),
        )
        return None if row is None else _dispute_row(row)

    def save_dispute(self, record: dict[str, Any]) -> None:
        self._execute(
            "UPDATE gab_disputes SET status = %s, outcome = %s, updated_at = %s WHERE dispute_id = %s",
            (record["status"], record.get("outcome"), record["updated_at"], record["dispute_id"]),
        )

    def reporter_types(self) -> dict[str, str]:
        rows = self._all("SELECT org_id, org_type FROM gab_organizations", ())
        return {row[0]: row[1] for row in rows}

    def _ensure(self) -> None:
        if self._ready:
            return
        import psycopg

        with psycopg.connect(self.schema_url, autocommit=True) as conn:
            for statement in migration_statements():
                conn.execute(statement)
            for path in sorted(_MIGRATIONS.glob("*.sql")):
                conn.execute(
                    "INSERT INTO gab_schema_migrations (version, applied_at) VALUES (%s, %s) ON CONFLICT (version) DO NOTHING",
                    (path.name, "applied"),
                )
        self._ready = True

    def _connect(self):
        import psycopg

        conn = psycopg.connect(self.database_url)
        if in_test_mode():
            conn.execute("SET search_path TO gab_sandbox, public")
        return conn

    def _execute(self, sql: str, params: tuple) -> None:
        self._ensure()
        with self._connect() as conn:
            conn.execute(sql, params)

    def _one(self, sql: str, params: tuple):
        self._ensure()
        with self._connect() as conn:
            return conn.execute(sql, params).fetchone()

    def _all(self, sql: str, params: tuple):
        self._ensure()
        with self._connect() as conn:
            return conn.execute(sql, params).fetchall()


def _key_row(row) -> dict[str, Any]:
    return {
        "key_id": row[0],
        "org_id": row[1],
        "name": row[2],
        "prefix": row[3],
        "secret_hash": row[4],
        "scopes": json.loads(row[5]),
        "created_at": row[6],
        "revoked_at": row[7],
        "rotated_from": row[8],
        "environment": row[9] if len(row) > 9 else "live",
    }


def _agent_row(row) -> dict[str, Any]:
    return {
        "agent_id": row[0],
        "operator_org_id": row[1],
        "principal_id": row[2],
        "status": row[3],
        "verification_level": row[4],
        "algorithm": row[5],
        "fingerprint": row[6],
        "public_key": json.loads(row[7]),
        "created_at": row[8],
        "updated_at": row[9],
        "score": row[10],
        "score_reasons": json.loads(row[11]),
        "cold_start": bool(row[12]),
        "principal_public_key": json.loads(row[13]) if len(row) > 13 and row[13] else None,
    }


def _agreement_row(row) -> dict[str, Any]:
    return {
        "agreement_id": row[0],
        "agent_id": row[1],
        "document": load_doc(row[2]),
        "status": row[3],
        "updated_at": row[4],
    }


def _report_row(row) -> dict[str, Any]:
    return {
        "report_id": row[0],
        "agent_id": row[1],
        "reporter_org_id": row[2],
        "kind": row[3],
        "evidence_hash": row[4],
        "summary": row[5],
        "outcome": row[6],
        "created_at": row[7],
        "excluded": bool(row[8]),
        "action_id": row[9] if len(row) > 9 else None,
    }


def _interaction_row(row) -> dict[str, Any]:
    return {
        "interaction_id": row[0],
        "agent_id": row[1],
        "operator_org_id": row[2],
        "counterparty_org_id": row[3],
        "action_id": row[4],
        "amount": row[5],
        "currency": row[6],
        "agreement_id": row[7],
        "at": row[8],
    }


def _sub_row(row) -> dict[str, Any]:
    return {
        "subscription_id": row[0],
        "org_id": row[1],
        "agent_id": row[2],
        "webhook_url": row[3],
        "created_at": row[4],
    }


def _dispute_row(row) -> dict[str, Any]:
    return {
        "dispute_id": row[0],
        "report_id": row[1],
        "principal_id": row[2],
        "statement": row[3],
        "status": row[4],
        "outcome": row[5],
        "created_at": row[6],
        "updated_at": row[7],
    }
