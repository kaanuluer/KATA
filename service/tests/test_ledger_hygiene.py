# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Ledger allow-list and detached payloads. SYNTHETIC TEST DATA only."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from urllib.parse import urlparse

import pytest
from fastapi.testclient import TestClient

from kata_service.asgi import create_app
from kata_service.audit_ledger import ROLLBACK_NOTE, count_documents, run
from kata_service.keys import EnvKeyProvider, open_detached
from kata_service.ledger import LedgerBodyError, check_body
from kata_service.settings import Settings, settings_from_env
from kata_service.store import MemoryStore

_HMAC = b"SYNTHETIC TEST DATA key-00000000"
_KEK = b"SYNTHETIC TEST DATA local-kek!!!"
_REF = b"SYNTHETIC TEST DATA subject-ref!"
assert len(_HMAC) == len(_KEK) == len(_REF) == 32
_PRINCIPAL = "prn_synthetic"


def test_production_stores_data_keys_in_the_database_and_the_allow_list_rejects_contact_fields():
    ring = json.dumps(
        {"sub-1": {"secret": base64.b64encode(_HMAC).decode(), "purposes": ["subject"], "active": True}}
    )
    for extra in ({}, {"GAB_SYNTHETIC_DATA": "1"}, {"GAB_ALLOW_ENV_KEYS": "1"}):
        refused = settings_from_env(
            {
                "GAB_LEDGER_HYGIENE": "1",
                "GAB_KEY_PROVIDER": "env",
                "GAB_HMAC_KEYS": ring,
                "GAB_MASTER_KEY": base64.b64encode(_KEK).decode(),
                "GAB_SUBJECT_REF_KEY": base64.b64encode(_REF).decode(),
                **extra,
            }
        )
        assert refused.key_provider is None
        assert "refused" in (refused.config_error or "")
    needs_database = settings_from_env(
        {
            "GAB_LEDGER_HYGIENE": "1",
            "GAB_KEY_PROVIDER": "aws-kms",
            "GAB_KMS_KEY_ID": "synthetic-kms-key",
            "GAB_KMS_REGION": "us-east-1",
        }
    )
    assert "gab_subject_deks" in (needs_database.config_error or "")
    assert "DATABASE_URL" in (needs_database.config_error or "")
    with pytest.raises(LedgerBodyError):
        check_body({"agent_id": "shopper-01", "email": "synthetic-test-data@example.com"})
    check_body({"agent_id": "shopper-01", "evidence_hash": "ab" * 32, "record_hash": "sha256:" + "cd" * 32})


def test_payload_dek_stays_out_of_the_row_and_erasure_drops_it():
    client = _client()
    appended = client.post(
        "/v1/log/entries",
        headers={"Authorization": "Bearer append-secret"},
        json={
            "kind": "incident",
            "body": {
                "agent_id": "shopper-01",
                "principal_id": _PRINCIPAL,
                "payload": {"note": "SYNTHETIC TEST DATA"},
            },
        },
    )
    assert appended.status_code == 200, appended.text
    entry = appended.json()["entry"]
    assert "payload" not in entry["body"]
    assert "principal_id" not in entry["body"]
    assert entry["body"]["payload_hash"].startswith("sha256:")
    assert entry["body"]["subject_ref"].startswith("v1:")
    bureau = client.app.state.bureau
    stored = next(iter(bureau.repo.payloads.values()))
    assert stored["ciphertext"].startswith("gabseal1.detached.")
    assert "embedded" not in stored["ciphertext"]
    wrapped = client.app.state.dek_store.get(_PRINCIPAL)
    assert wrapped is not None
    opened = open_detached(
        _provider(),
        stored["ciphertext"],
        wrapped,
        subject_id=_PRINCIPAL,
    )
    assert b"SYNTHETIC TEST DATA" in opened
    erased = client.post(
        "/internal/erasure",
        headers={"Authorization": "Bearer admin-test-token"},
        json={"subject_id": _PRINCIPAL},
    )
    assert erased.status_code == 200, erased.text
    assert erased.json()["destroyed"] is True
    assert client.app.state.dek_store.get(_PRINCIPAL) is None
    assert client.get("/v1/log/entries/1").json()["entry"]["body"]["agent_id"] == "shopper-01"
    correction = client.post(
        "/v1/log/corrections",
        headers={"Authorization": "Bearer append-secret"},
        json={"corrects_sequence": 1, "record_hash": entry["entry_hash"]},
    )
    assert correction.status_code == 200, correction.text
    assert client.get("/v1/log/entries/1").json()["entry"]["body"]["agent_id"] == "shopper-01"
    assert correction.json()["entry"]["kind"] == "correction"
    rejected = client.post(
        "/v1/log/entries",
        headers={"Authorization": "Bearer append-secret"},
        json={"kind": "incident", "body": {"email": "synthetic-test-data@example.com"}},
    )
    assert rejected.status_code == 400


def test_audit_script_counts_without_connecting(capsys):
    assert run([]) == 0
    text = capsys.readouterr().out
    assert ROLLBACK_NOTE in text
    assert "dry-run" in text
    assert run(["--execute"]) == 2
    counts = count_documents(
        [
            '{"body":{"agent_id":"shopper-01"}}',
            '{"body":{"email":"synthetic-test-data@example.com"}}',
        ]
    )
    assert counts.scanned == 2
    assert counts.clean == 1
    assert counts.flagged == 1


def test_flag_off_still_appends_a_free_body():
    settings = Settings(
        None,
        None,
        hashlib.sha256(b"SYNTHETIC TEST DATA ledger seed").digest(),
        None,
        "append-secret",
        (),
        "https://fx.test",
        admin_token="admin-test-token",
    )
    client = TestClient(create_app(settings, MemoryStore()))
    response = client.post(
        "/v1/log/entries",
        headers={"Authorization": "Bearer append-secret"},
        json={"kind": "incident", "body": {"email": "synthetic-test-data@example.com"}},
    )
    assert response.status_code == 200, response.text
    assert response.json()["entry"]["body"]["email"] == "synthetic-test-data@example.com"
    assert client.post(
        "/internal/erasure",
        headers={"Authorization": "Bearer admin-test-token"},
        json={"subject_id": _PRINCIPAL},
    ).status_code == 404


def test_postgres_payload_table():
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
    PostgresRepo(url, url).migration_versions()
    with psycopg.connect(url) as conn:
        row = conn.execute("SELECT to_regclass('public.gab_payloads')").fetchone()
    assert row[0] == "gab_payloads"


def _provider() -> EnvKeyProvider:
    return EnvKeyProvider(
        {
            "sub-1": {"secret": _HMAC, "purposes": ["subject"], "active": True},
            "kek-1": {"secret": _KEK, "purposes": ["kek"], "active": True},
        },
        subject_key=_REF,
    )


def _client() -> TestClient:
    settings = Settings(
        None,
        None,
        hashlib.sha256(b"SYNTHETIC TEST DATA ledger seed").digest(),
        None,
        "append-secret",
        (),
        "https://fx.test",
        admin_token="admin-test-token",
        deployment_env="sandbox",
        key_provider=_provider(),
        ledger_hygiene=True,
    )
    return TestClient(create_app(settings, MemoryStore()))
