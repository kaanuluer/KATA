# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Breach register. SYNTHETIC TEST DATA only. No production database."""

from __future__ import annotations

import json
import os
from urllib.parse import urlparse

import pytest
from fastapi.testclient import TestClient

from kata_service.asgi import create_app, ensure_bureau
from kata_service.breach import (
    BREACH_RETENTION_YEARS,
    access_chain_ok,
    chain_ok,
    notice_text,
    retain_until,
)
from kata_service.bureau import BureauError, BureauService, MemoryRepo
from kata_service.bureau_pg import migration_statements
from kata_service.settings import Settings, settings_from_env
from kata_service.store import MemoryStore

_NOTE = "sha256:" + "ab" * 32


def test_retention_is_five_years_and_labels_are_types_only():
    assert BREACH_RETENTION_YEARS == 5
    assert settings_from_env({}).breach_tools is False
    assert retain_until("2026-10-17T00:00:00Z") == "2031-10-17T00:00:00Z"
    assert retain_until("2024-02-29T12:00:00Z") == "2029-02-28T12:00:00Z"
    service = BureauService(MemoryRepo(), breach_tools=True)
    with pytest.raises(BureauError, match="type labels"):
        service.record_breach(
            {
                "detected_at": "2026-10-17T00:00:00Z",
                "data_types": ["synthetic-test-data@example.com"],
            }
        )
    saved = service.record_breach(
        {
            "detected_at": "2026-10-17T00:00:00Z",
            "data_types": ["email", "credential"],
            "scope_count": 2,
            "note_hash": _NOTE,
        }
    )
    assert saved["retain_until"] == "2031-10-17T00:00:00Z"
    assert saved["data_types"] == ["email", "credential"]
    assert "@" not in json.dumps(saved)
    text = notice_text(saved["data_types"], saved["detected_at"])
    assert "legal determination" in text
    assert "certified" not in text.lower()
    assert "compliant" not in text.lower()
    bodies = [
        item
        for item in migration_statements()
        if "CREATE OR REPLACE FUNCTION gab_reject_breach_mutation" in item
    ]
    assert len(bodies) == 1
    assert "RAISE EXCEPTION 'gab_breach_register is append-only'" in bodies[0]


def test_chain_and_access_log_omit_the_recipient():
    service = BureauService(MemoryRepo(), breach_tools=True)
    with pytest.raises(BureauError, match="breach tools are off"):
        BureauService(MemoryRepo()).record_breach({"detected_at": "2026-10-17T00:00:00Z", "data_types": ["email"]})
    first = service.record_breach({"detected_at": "2026-10-17T00:00:00Z", "data_types": ["email"]})
    second = service.record_breach({"detected_at": "2026-10-17T01:00:00Z", "data_types": ["phone"], "scope_count": 0})
    assert chain_ok(service.repo.list_breach()) is True
    assert second["prev_hash"] == first["entry_hash"]
    with pytest.raises(BureauError, match="append-only"):
        service.repo.delete_breach(first["event_id"])
    held = service.notify_breach({"event_id": first["event_id"], "to": "synthetic-test-data@example.com"})
    assert held["sent"] is False
    assert "synthetic-test-data@example.com" not in held["notice"]
    listed = service.list_breaches()
    assert listed[0]["event_id"] == first["event_id"]
    access = service.repo.list_access()
    assert access_chain_ok(access) is True
    assert [item["action"] for item in access] == ["notify", "list"]
    assert "@" not in json.dumps(access)
    with pytest.raises(BureauError, match="append-only"):
        service.repo.delete_access(access[0]["access_id"])


def test_routes_stay_dark_until_the_flag_and_revoke_returns_counts():
    dark = _client()
    assert dark.post("/internal/breach", json={"data_types": ["email"]}).status_code == 404
    assert dark.get("/internal/breach").status_code == 404
    client = _client(breach_tools=True)
    refused = client.post(
        "/internal/breach",
        json={"detected_at": "2026-10-17T00:00:00Z", "data_types": ["email"]},
    )
    assert refused.status_code == 401
    created = client.post(
        "/internal/breach",
        headers=_admin(),
        json={"detected_at": "2026-10-17T00:00:00Z", "data_types": ["credential"], "note_hash": _NOTE},
    )
    assert created.status_code == 200, created.text
    bureau = ensure_bureau(client.app)
    bureau.repo.put_session(
        {"token_hash": "session-synthetic", "kind": "portal", "subject_id": "prn_synthetic", "expires_at": "2099-01-01T00:00:00Z"}
    )
    bureau.repo.put_magic(
        {
            "token_hash": "magic-synthetic",
            "kind": "portal",
            "subject_hash": "subject-synthetic",
            "expires_at": "2099-01-01T00:00:00Z",
            "used_at": None,
        }
    )
    bureau.repo.create_key({"key_id": "key-synthetic", "secret_hash": "hash-synthetic", "revoked_at": None})
    bureau.repo.put_passkey({"credential_id": "passkey-synthetic", "principal_id": "prn_synthetic"})
    revoked = client.post("/internal/breach/revoke", headers=_admin())
    assert revoked.status_code == 200, revoked.text
    counts = revoked.json()
    assert counts == {"sessions": 1, "magic_links": 1, "api_keys": 1, "passkeys": 1}
    assert bureau.repo.sessions["session-synthetic"]["expires_at"] < "2099-01-01T00:00:00Z"
    assert bureau.repo.magic["magic-synthetic"]["used_at"]
    assert bureau.repo.keys["key-synthetic"]["revoked_at"]
    assert bureau.repo.passkeys == {}
    quiet = client.post(
        "/internal/breach/notify",
        headers=_admin(),
        json={"event_id": created.json()["event_id"], "send": True, "to": "synthetic-test-data@example.com"},
    )
    assert quiet.status_code == 409
    mailer = _NoticeMailer()
    bureau.mailer = mailer
    sent = client.post(
        "/internal/breach/notify",
        headers=_admin(),
        json={"event_id": created.json()["event_id"], "send": True, "to": "synthetic-test-data@example.com"},
    )
    assert sent.status_code == 200, sent.text
    assert sent.json()["sent"] is True
    assert mailer.sent[0][0] == "synthetic-test-data@example.com"
    assert "synthetic-test-data@example.com" not in sent.json()["notice"]
    assert "@" not in json.dumps(bureau.repo.list_access())


def test_postgres_trigger_blocks_mutation_and_revoke_counts_rows():
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
        conn.execute("DROP SCHEMA IF EXISTS gab_sandbox CASCADE")
        conn.execute("CREATE SCHEMA public")
        conn.execute("GRANT ALL ON SCHEMA public TO public")
    repo = PostgresRepo(url, url)
    saved = repo.append_breach(
        {
            "event_id": "brc_synthetic",
            "detected_at": "2026-10-17T00:00:00Z",
            "data_types": ["email"],
            "scope_count": 1,
            "note_hash": _NOTE,
        }
    )
    assert chain_ok(repo.list_breach()) is True
    assert saved["retain_until"] == "2031-10-17T00:00:00Z"
    with pytest.raises(BureauError, match="append-only"):
        repo.delete_breach(saved["event_id"])
    with psycopg.connect(url) as conn:
        with pytest.raises(psycopg.Error, match="append-only"):
            conn.execute("UPDATE gab_breach_register SET scope_count = 9")
    with psycopg.connect(url) as conn:
        conn.execute(
            """
            INSERT INTO gab_sessions (token_hash, kind, subject_id, expires_at)
            VALUES ('session-synthetic', 'portal', 'prn_synthetic', '2099-01-01T00:00:00Z')
            """
        )
        conn.execute(
            """
            INSERT INTO gab_magic_links (token_hash, kind, subject_hash, expires_at)
            VALUES ('magic-synthetic', 'portal', 'subject-synthetic', '2099-01-01T00:00:00Z')
            """
        )
        conn.execute(
            """
            INSERT INTO gab_api_keys (key_id, org_id, name, prefix, secret_hash, scopes, created_at)
            VALUES ('key-synthetic', 'org-synthetic', 'SYNTHETIC TEST DATA', 'syn', 'hash-synthetic', '[]', '2026-10-17T00:00:00Z')
            """
        )
        conn.execute(
            """
            INSERT INTO gab_passkeys (credential_id, principal_id, public_key, sign_count, label, created_at)
            VALUES ('passkey-synthetic', 'prn_synthetic', 'SYNTHETIC TEST DATA', 0, 'synthetic', '2026-10-17T00:00:00Z')
            """
        )
        conn.commit()
    counts = repo.revoke_credentials("2026-10-17T12:00:00Z")
    assert counts == {"sessions": 1, "magic_links": 1, "api_keys": 1, "passkeys": 1}
    logged = repo.append_access(
        {"access_id": "acc_synthetic", "at": "2026-10-17T12:00:00Z", "actor": "admin", "action": "revoke"}
    )
    assert access_chain_ok(repo.list_access()) is True
    with pytest.raises(BureauError, match="append-only"):
        repo.delete_access(logged["access_id"])


def _client(**overrides) -> TestClient:
    settings = Settings(
        None,
        None,
        None,
        None,
        None,
        (),
        "https://fx.test",
        admin_token="admin-test-token",
        **overrides,
    )
    return TestClient(create_app(settings, MemoryStore()))


def _admin() -> dict[str, str]:
    return {"Authorization": "Bearer admin-test-token"}


class _NoticeMailer:
    def __init__(self) -> None:
        self.sent: list[tuple[str, str]] = []

    def send_magic_link(self, email: str, url: str) -> None:
        return None

    def send_notice(self, email: str, text: str) -> None:
        self.sent.append((email, text))
