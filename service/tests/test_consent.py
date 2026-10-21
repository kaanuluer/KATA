# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Consent events. SYNTHETIC TEST DATA only. No production database."""

from __future__ import annotations

import os
from urllib.parse import urlparse

import pytest

from kata_service.bureau import Auth, BureauError, BureauService, MemoryRepo
from kata_service.bureau_pg import migration_statements
from kata_service.consent import chain_ok, manifest_matches_files, notice
from kata_service.copy_push_consent import BACKUP_PHRASE, ROLLBACK_NOTE, apply_plan, gate_errors, parse_args, plan_rows, run
from kata_service.portal_devices import register_push
from kata_service.settings import settings_from_env

from test_bureau import _auth, _client, _key, _org


def test_flags_default_off_and_manifest_matches():
    settings = settings_from_env({})
    assert settings.consent_events is False
    assert settings.consent_push is False
    assert settings.consent_network is False
    assert settings_from_env({"GAB_CONSENT_PUSH": "1"}).config_error == "consent purposes need GAB_CONSENT_EVENTS=1"
    assert manifest_matches_files() is True
    assert notice("push")["text_sha256"]


def test_trigger_function_stays_one_statement():
    bodies = [
        item
        for item in migration_statements()
        if "CREATE OR REPLACE FUNCTION gab_reject_consent_mutation" in item
    ]
    assert len(bodies) == 1
    assert "RAISE EXCEPTION 'gab_consent_events is append-only'" in bodies[0]
    assert "CREATE TABLE IF NOT EXISTS gab_consent_events" in "\n".join(migration_statements())
    assert "credit bureau" not in "\n".join(migration_statements()).lower()


def test_chain_is_append_only_and_source_ref_is_idempotent():
    service = _service(consent_events=True, consent_push=True, consent_network=True)
    auth = Auth(principal_id="prn_synthetic", kind="portal")
    first = service.record_consent(auth, {"purpose": "network", "granted": True, "text_version": "v1"})
    second = service.record_consent(auth, {"purpose": "push", "granted": False})
    rows = service.repo.list_consent()
    assert chain_ok(rows) is True
    assert first["prev_hash"] == ""
    assert second["prev_hash"] == first["entry_hash"]
    again = service.repo.append_consent(
        {
            "event_id": "cns_other",
            "principal_id": "prn_synthetic",
            "purpose": "push",
            "granted": True,
            "text_version": first["text_version"],
            "text_sha256": notice("push")["text_sha256"],
            "at": "2026-10-17T00:00:00Z",
            "source_ref": "psh_same",
        }
    )
    repeat = service.repo.append_consent(
        {
            "event_id": "cns_ignored",
            "principal_id": "prn_synthetic",
            "purpose": "push",
            "granted": True,
            "text_version": again["text_version"],
            "text_sha256": again["text_sha256"],
            "at": again["at"],
            "source_ref": "psh_same",
        }
    )
    assert repeat["event_id"] == again["event_id"]
    assert len(service.repo.list_consent()) == 3
    with pytest.raises(BureauError, match="append-only"):
        service.repo.delete_consent(first["event_id"])


def test_push_registration_writes_an_event_only_when_the_purpose_is_on(monkeypatch):
    body = {
        "consent": True,
        "endpoint": "https://push.example/synthetic",
        "keys": {"p256dh": "abc", "auth": "def"},
        "credential_id": "credential-not-a-device",
    }
    off = _service()
    auth = Auth(principal_id="prn_synthetic", kind="portal")
    stored = register_push(off, auth, body)
    assert stored["device_id"].startswith("psh_")
    assert stored["device_id"] != body["credential_id"]
    assert off.repo.list_consent() == []
    monkeypatch.setattr("kata_service.portal_devices._id", lambda prefix: "psh_same")
    with pytest.raises(BureauError, match="credential"):
        register_push(off, auth, {**body, "credential_id": "psh_same"})
    on = _service(consent_events=True, consent_push=True)
    created = register_push(on, auth, body)
    events = on.repo.list_consent("prn_synthetic", "push")
    assert len(events) == 1
    assert events[0]["source_ref"] == created["device_id"]
    assert events[0]["granted"] is True
    assert chain_ok(events) is True
    with pytest.raises(BureauError, match="catalog"):
        register_push(on, auth, {**body, "text_version": "v9"})


def test_network_signal_requires_a_consent_event_when_the_flag_is_on():
    client = _client(consent_events=True, consent_network=True)
    operator = _org(client, "Synthetic Operator", "agent_operator")
    operator_key = _key(client, operator["org_id"])
    refused = client.post(
        "/v1/agents",
        headers=_auth(operator_key),
        json={
            **_agent_body(),
            "device_signal": "synthetic-device",
        },
    )
    assert refused.status_code == 403
    assert refused.json()["error"] == "network purpose needs a consent event"
    _portal(client, "prn_synthetic")
    granted = client.post(
        "/v1/portal/consent",
        headers=_auth("synthetic-portal-token"),
        json={"purpose": "network", "granted": True},
    )
    assert granted.status_code == 200, granted.text
    assert granted.json()["text_sha256"] == notice("network")["text_sha256"]
    accepted = client.post(
        "/v1/agents",
        headers=_auth(operator_key),
        json={**_agent_body(), "device_signal": "synthetic-device"},
    )
    assert accepted.status_code == 200, accepted.text
    assert accepted.json()["agent_id"] == "shopper-01"
    quiet = client.post("/v1/portal/consent", json={"purpose": "network", "granted": True})
    assert quiet.status_code == 401
    disabled = _client()
    _portal(disabled, "prn_synthetic")
    blocked = disabled.post(
        "/v1/portal/consent",
        headers=_auth("synthetic-portal-token"),
        json={"purpose": "network", "granted": True},
    )
    assert blocked.status_code == 404


def test_copy_script_is_dry_run_and_idempotent(capsys):
    assert run([]) == 0
    captured = capsys.readouterr().out
    assert ROLLBACK_NOTE in captured
    assert "dry-run" in captured
    assert run(["--execute"]) == 2
    args = parse_args(
        [
            "--execute",
            "--approve",
            "--backup-confirmed-id", "snap-synthetic-01",
            "--backup-confirmed-at", "2026-10-17",
            "--backup-phrase", BACKUP_PHRASE,
            "--database-url", "postgresql://postgres:postgres@127.0.0.1:5432/gab",
        ]
    )
    assert gate_errors(args) == []
    plan = plan_rows(
        [
            {"device_id": "psh_one", "principal_id": "prn_synthetic", "consent_at": "2026-10-17T00:00:00Z"},
            {"device_id": "psh_one", "principal_id": "prn_synthetic", "consent_at": "2026-10-17T00:00:00Z"},
            {"device_id": "", "principal_id": "prn_synthetic", "consent_at": "2026-10-17T00:00:00Z"},
        ],
        [],
        event_id_for=lambda device_id: "cns_" + device_id,
    )
    assert plan.insert == 1
    assert plan.skip == 2
    conn = _FakeConn()
    assert apply_plan(conn, plan) == 1
    assert apply_plan(conn, plan) == 0
    assert "psh_one" in conn.calls[0][1]


def test_postgres_consent_trigger_blocks_delete():
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
    saved = repo.append_consent(
        {
            "event_id": "cns_synthetic",
            "principal_id": "prn_synthetic",
            "purpose": "push",
            "granted": True,
            "text_version": "v1",
            "text_sha256": notice("push")["text_sha256"],
            "at": "2026-10-17T00:00:00Z",
            "source_ref": "psh_synthetic",
        }
    )
    assert chain_ok(repo.list_consent()) is True
    with pytest.raises(BureauError, match="append-only"):
        repo.delete_consent(saved["event_id"])
    assert repo.list_consent()[0]["event_id"] == "cns_synthetic"


def _service(**kwargs) -> BureauService:
    return BureauService(MemoryRepo(), **kwargs)


def _agent_body() -> dict:
    from test_bureau import _agent_keys

    _principal, agent = _agent_keys()
    return {
        "agent_id": "shopper-01",
        "principal_id": "prn_synthetic",
        "public_key": agent.public.to_jwk(),
        "verification_level": "operator_verified",
    }


def _portal(client, principal_id: str) -> None:
    from kata_service.asgi import ensure_bureau
    from kata_service.bureau import token_hash

    bureau = ensure_bureau(client.app)
    bureau.repo.put_session(
        {
            "token_hash": token_hash("synthetic-portal-token"),
            "kind": "portal",
            "subject_id": principal_id,
            "expires_at": "2099-01-01T00:00:00Z",
        }
    )


class _FakeConn:
    def __init__(self) -> None:
        self.calls: list[tuple] = []
        self._hashes: list[str] = []
        self._refs: set[str] = set()

    def execute(self, sql: str, params=()):
        self.calls.append((sql, params))
        parent = self

        class _Result:
            def fetchone(_self):
                if "source_ref" in sql and "SELECT" in sql:
                    return ("existing",) if params and params[0] in parent._refs else None
                if "entry_hash" in sql and "SELECT" in sql:
                    return None if not parent._hashes else (parent._hashes[-1],)
                return None

        if sql.strip().startswith("INSERT"):
            parent._refs.add(params[7])
            parent._hashes.append(params[9])
        return _Result()
