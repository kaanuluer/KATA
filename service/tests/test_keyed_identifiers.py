# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Keyed identifiers. SYNTHETIC TEST DATA only. No production database."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

import pytest
from fastapi.testclient import TestClient

from kata_service.asgi import create_app
from kata_service.backfill_identifiers import BACKUP_PHRASE, ROLLBACK_NOTE, apply_plan, gate_errors, parse_args, plan_rows, run
from kata_service.bureau import BureauService, MemoryRepo, email_hash, token_hash
from kata_service.keys import EnvKeyProvider, _hmac_key, hmac_message
from kata_service.settings import settings_from_env

# SYNTHETIC TEST DATA. 32-byte labels, not credentials.
_HMAC_KEY = b"SYNTHETIC TEST DATA key-00000000"
_HMAC_KEY_OLD = b"SYNTHETIC TEST DATA key-old!!!!!"
_KEK = b"SYNTHETIC TEST DATA local-kek!!!"
_REF = b"SYNTHETIC TEST DATA subject-ref!"
_EMAIL = "synthetic-test-data@example.com"
assert len(_HMAC_KEY) == len(_HMAC_KEY_OLD) == len(_KEK) == 32


class _QuietMail:
    def send_magic_link(self, email: str, url: str) -> None:
        return None


def _provider(*, active_new: bool = True) -> EnvKeyProvider:
    return EnvKeyProvider(
        {
            "email-old": {"secret": _HMAC_KEY_OLD, "purposes": ["identifier"], "active": not active_new},
            "email-new": {"secret": _HMAC_KEY, "purposes": ["identifier"], "active": active_new},
            "ip-1": {"secret": _HMAC_KEY, "purposes": ["rate"], "active": True},
            "local-kek": {"secret": _KEK, "purposes": ["kek"], "active": True},
            "subject-ref": {"secret": _REF, "purposes": ["ref"], "active": True},
        }
    )


def _env_json() -> str:
    import base64

    def b64(raw: bytes) -> str:
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    return json.dumps(
        {
            "email-new": {"secret": b64(_HMAC_KEY), "purposes": ["identifier"], "active": True},
            "ip-1": {"secret": b64(_HMAC_KEY), "purposes": ["rate"], "active": True},
            "local-kek": {"secret": b64(_KEK), "purposes": ["kek"], "active": True},
            "subject-ref": {"secret": b64(_REF), "purposes": ["ref"], "active": True},
        }
    )


def _service(repo=None, **kwargs) -> BureauService:
    return BureauService(repo or MemoryRepo(), mailer=_QuietMail(), dev_mailbox=True, **kwargs)


def test_flag_off_keeps_unsalted_email_hash_and_plaintext():
    service = _service()
    service.request_portal_link(_EMAIL)
    digest = email_hash(_EMAIL)
    row = service.repo.logins[digest]
    assert row["email"] == _EMAIL
    assert "email_hmac" not in row
    assert service.repo.login_by_email(_EMAIL)["principal_id"].startswith("prn_")
    magic = next(iter(service.repo.magic.values()))
    assert magic["subject_hash"] == digest
    assert "subject_hmac" not in magic
    assert token_hash("synthetic-token") == hashlib.sha256(b"synthetic-token").hexdigest()


def test_keyed_mode_dual_reads_legacy_rows_and_encrypts_new_writes():
    provider = _provider()
    repo = MemoryRepo()
    digest = email_hash(_EMAIL)
    repo.logins[digest] = {
        "email_hash": digest,
        "email": _EMAIL,
        "principal_id": "prn_synthetic",
        "created_at": "2026-10-17T00:00:00Z",
    }
    service = _service(repo=repo, key_provider=provider, keyed_identifiers=True)
    found = service.repo.login_by_email(_EMAIL)
    assert found["principal_id"] == "prn_synthetic"
    assert found["email"] == _EMAIL
    assert service.repo.insert_login(_EMAIL, "prn_synthetic", "2026-10-17T00:00:00Z") == "same"
    stored = repo.logins[digest]
    assert stored["email"] == _EMAIL
    assert stored["email_hmac"].startswith("v1:email-new:")
    assert provider.unseal(stored["email_ciphertext"], subject_id="prn_synthetic").decode() == _EMAIL
    assert email_hash(_EMAIL) == digest
    service.request_portal_link(_EMAIL)
    magic = next(iter(service.repo.magic.values()))
    assert magic["subject_hmac"] == stored["email_hmac"]
    assert magic["subject_hash"] == digest
    consumed = service.consume_link(service.dev_mailbox[-1]["token"])
    assert consumed["principal_id"] == "prn_synthetic"


def test_strict_mode_stops_plaintext_and_unsalted_hash_on_new_rows():
    provider = _provider()
    service = _service(key_provider=provider, keyed_identifiers=True, stop_plaintext_email=True)
    assert service.repo.insert_login(_EMAIL, "prn_synthetic", "2026-10-17T00:00:00Z") == "inserted"
    assert email_hash(_EMAIL) not in service.repo.logins
    stored = next(iter(service.repo.logins.values()))
    assert stored["email"] == ""
    assert stored["email_hash"].startswith("v1:email-new:")
    revealed = service.repo.login_by_email(_EMAIL)
    assert revealed["email"] == _EMAIL
    assert revealed["principal_id"] == "prn_synthetic"
    service.request_portal_link(_EMAIL)
    magic = next(iter(service.repo.magic.values()))
    assert magic["subject_hash"] == stored["email_hash"]
    assert service.consume_link(service.dev_mailbox[-1]["token"])["principal_id"] == "prn_synthetic"


def test_old_kid_still_finds_a_row_after_rotation():
    old = _provider(active_new=False)
    service = _service(key_provider=old, keyed_identifiers=True)
    service.repo.insert_login(_EMAIL, "prn_synthetic", "2026-10-17T00:00:00Z")
    rotated = _service(repo=service.repo, key_provider=_provider(active_new=True), keyed_identifiers=True)
    found = rotated.repo.login_by_email(_EMAIL)
    assert found["principal_id"] == "prn_synthetic"
    rotated.repo.insert_login(_EMAIL, "prn_synthetic", "2026-10-17T01:00:00Z")
    stored = rotated.repo.logins[email_hash(_EMAIL)]
    assert stored["email_kid"] == "email-new"


def test_rate_subject_is_hmac_and_rows_older_than_24h_are_purged():
    moment = datetime(2026, 10, 17, 12, 0, tzinfo=timezone.utc)
    provider = _provider()
    service = _service(
        key_provider=provider,
        hmac_rate_subject=True,
        now=lambda: moment,
    )
    service.repo.rate[("203.0.113.9", "2026-10-16T11:00")] = 4
    service.repo.rate[("203.0.113.9", "2026-10-17T11:30")] = 1
    service.hit_rate("ignored")
    assert ("203.0.113.9", "2026-10-16T11:00") not in service.repo.rate
    assert ("203.0.113.9", "2026-10-17T11:30") in service.repo.rate
    settings = settings_from_env(
        {
            "GAB_HMAC_RATE_SUBJECT": "1",
            "GAB_KEY_PROVIDER": "env",
            "GAB_ENV": "sandbox",
            "GAB_HMAC_KEYS": _env_json(),
        }
    )
    client = TestClient(create_app(settings))
    client.post("/v1/orgs", json={"name": "SYNTHETIC TEST DATA", "org_type": "merchant"})
    subjects = [key[0] for key in client.app.state.bureau.repo.rate]
    assert subjects
    assert all(item != "testclient" for item in subjects)
    assert any(item.startswith("v1:ip-1:") for item in subjects)
    raw = client_without = settings_from_env({})
    assert raw.hmac_rate_subject is False
    plain = TestClient(create_app(client_without))
    plain.post("/v1/orgs", json={"name": "SYNTHETIC TEST DATA", "org_type": "merchant"})
    assert any(key[0] == "testclient" for key in plain.app.state.bureau.repo.rate)


def test_flags_default_off_and_fail_closed_without_a_provider():
    plain = settings_from_env({})
    assert plain.keyed_identifiers is False
    assert plain.hmac_rate_subject is False
    assert plain.stop_plaintext_email is False
    missing = settings_from_env({"GAB_KEYED_IDENTIFIERS": "1"})
    assert missing.key_provider is None
    assert "GAB_KEY_PROVIDER" in (missing.config_error or "")
    early = settings_from_env({"GAB_STOP_PLAINTEXT_EMAIL": "1"})
    assert "GAB_KEYED_IDENTIFIERS" in (early.config_error or "")


def test_backfill_is_dry_run_unless_backup_and_approval_are_present(capsys):
    def explode(_url: str):
        raise AssertionError("database connection was opened")

    assert run([], connect=explode) == 0
    dry = capsys.readouterr().out
    assert "dry-run" in dry
    assert ROLLBACK_NOTE in dry
    refused = run(["--execute", "--database-url", "postgresql://example.invalid/gab"], connect=explode)
    assert refused == 2
    text = capsys.readouterr().out
    assert "refusing" in text
    assert "postgresql://example.invalid/gab" not in text
    args = parse_args(
        [
            "--execute",
            "--approve",
            "--backup-confirmed-id", "snap-synthetic-001",
            "--backup-confirmed-at", "2026-10-17T00:00:00Z",
            "--backup-phrase", BACKUP_PHRASE,
            "--database-url", "postgresql://example.invalid/gab",
        ]
    )
    assert gate_errors(args) == []


def test_backfill_plan_is_idempotent_on_synthetic_rows():
    provider = _provider()
    rows = [
        {
            "table": "gab_logins",
            "email_hash": email_hash(_EMAIL),
            "email": _EMAIL,
            "subject_id": "prn_synthetic",
            "email_hmac": None,
            "email_ciphertext": None,
        }
    ]
    first = plan_rows(rows, provider, strip_plaintext=False)
    assert first.update == 1 and first.skip == 0 and first.unreadable == 0
    action = first.actions[0]
    assert action["email"] == _EMAIL
    assert action["email_hmac"].startswith("v1:email-new:")
    assert _EMAIL not in action["email_hmac"]
    second_row = {
        **rows[0],
        "email_hmac": action["email_hmac"],
        "email_ciphertext": action["email_ciphertext"],
    }
    second = plan_rows([second_row], provider, strip_plaintext=False)
    assert second.update == 0 and second.skip == 1
    stripped = plan_rows([second_row], provider, strip_plaintext=True)
    assert stripped.update == 1 and stripped.actions[0]["email"] == ""
    again = plan_rows(
        [{**second_row, "email": "", "email_hmac": stripped.actions[0]["email_hmac"], "email_ciphertext": stripped.actions[0]["email_ciphertext"]}],
        provider,
        strip_plaintext=True,
    )
    assert again.skip == 1

    class _Conn:
        def __init__(self):
            self.calls = []

        def execute(self, sql, params=None):
            self.calls.append(params)
            return self

    conn = _Conn()
    assert apply_plan(conn, first) == 1
    assert conn.calls[0][0] == _EMAIL
    message = hmac.new(
        _hmac_key(_HMAC_KEY, "identifier"),
        hmac_message("identifier", _EMAIL),
        hashlib.sha256,
    ).hexdigest()
    assert message in action["email_hmac"]


def test_postgres_migration_adds_keyed_columns():
    url = os.environ.get("GAB_TEST_DATABASE_URL")
    if not url:
        if os.environ.get("GITHUB_ACTIONS"):
            pytest.fail("GAB_TEST_DATABASE_URL is required in CI")
        pytest.skip("GAB_TEST_DATABASE_URL is not set")
    if urlparse(url).hostname not in {"localhost", "127.0.0.1"}:
        pytest.fail("GAB_TEST_DATABASE_URL must point at localhost")
    import psycopg

    from kata_service.bureau_pg import PostgresRepo

    with psycopg.connect(url, autocommit=True) as conn:
        conn.execute("DROP SCHEMA IF EXISTS public CASCADE")
        conn.execute("CREATE SCHEMA public")
        conn.execute("GRANT ALL ON SCHEMA public TO public")
    repo = PostgresRepo(url, url)
    repo.migration_versions()
    with psycopg.connect(url) as conn:
        columns = {
            (row[0], row[1])
            for row in conn.execute(
                """
                SELECT table_name, column_name FROM information_schema.columns
                WHERE table_name IN ('gab_logins', 'gab_org_logins', 'gab_magic_links')
                """
            ).fetchall()
        }
    assert ("gab_logins", "email_hmac") in columns
    assert ("gab_logins", "email_ciphertext") in columns
    assert ("gab_org_logins", "email_kid") in columns
    assert ("gab_magic_links", "subject_hmac") in columns
    provider = _provider()
    service = BureauService(repo, mailer=_QuietMail(), key_provider=provider, keyed_identifiers=True)
    assert service.repo.insert_login(_EMAIL, "prn_synthetic", "2026-10-17T00:00:00Z") == "inserted"
    found = service.repo.login_by_email(_EMAIL)
    assert found["email"] == _EMAIL
    assert found["principal_id"] == "prn_synthetic"
    other = "synthetic-legacy@example.com"
    with psycopg.connect(url) as conn:
        conn.execute(
            "INSERT INTO gab_logins (email_hash, email, principal_id, created_at) VALUES (%s, %s, %s, %s)",
            (email_hash(other), other, "prn_legacy", "2026-10-16T00:00:00Z"),
        )
        conn.commit()
    assert service.repo.login_by_email(other)["principal_id"] == "prn_legacy"
    assert service.repo.insert_login(other, "prn_legacy", "2026-10-17T00:00:00Z") == "same"
    with psycopg.connect(url) as conn:
        saved = conn.execute(
            "SELECT email, email_hmac FROM gab_logins WHERE principal_id = %s",
            ("prn_legacy",),
        ).fetchone()
    assert saved[0] == other
    assert saved[1].startswith("v1:email-new:")
    stale = (moment_old := (datetime(2026, 10, 17, 12, tzinfo=timezone.utc) - timedelta(hours=25))).strftime("%Y-%m-%dT%H:%M")
    with psycopg.connect(url) as conn:
        conn.execute("INSERT INTO gab_rate (subject, window_start, hits) VALUES (%s, %s, %s)", ("203.0.113.9", stale, 2))
        conn.commit()
    service.hmac_rate_subject = True
    service._rate_purged_before = None
    service._now = lambda: datetime(2026, 10, 17, 12, tzinfo=timezone.utc)
    service.hit_rate("v1:ip-1:synthetic")
    with psycopg.connect(url) as conn:
        left = conn.execute("SELECT subject FROM gab_rate WHERE subject = %s", ("203.0.113.9",)).fetchone()
    assert left is None
    assert moment_old
