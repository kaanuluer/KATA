# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Register, report, and attest through PostgresRepo.

The memory repository never calls PostgresRepo._all. A missing params argument
there is a TypeError only on this path.
"""

from __future__ import annotations

import os
import threading
from urllib.parse import urlparse

import pytest

from kata_service.bureau_pg import PostgresRepo


def _database_url() -> str:
    url = os.environ.get("GAB_TEST_DATABASE_URL")
    if not url:
        if os.environ.get("GITHUB_ACTIONS"):
            pytest.fail("GAB_TEST_DATABASE_URL is required in CI")
        pytest.skip("GAB_TEST_DATABASE_URL is not set")
    host = urlparse(url).hostname
    if host not in {"localhost", "127.0.0.1"}:
        pytest.fail("GAB_TEST_DATABASE_URL must point at localhost")
    return url


def _reset(url: str) -> None:
    import psycopg

    with psycopg.connect(url, autocommit=True) as conn:
        conn.execute("DROP SCHEMA IF EXISTS gab_sandbox CASCADE")
        conn.execute("DROP SCHEMA IF EXISTS public CASCADE")
        conn.execute("CREATE SCHEMA public")
        conn.execute("GRANT ALL ON SCHEMA public TO public")


def test_concurrent_schema_setup_does_not_collide():
    url = _database_url()
    _reset(url)
    errors: list[BaseException] = []

    def boot() -> None:
        try:
            PostgresRepo(url, url).migration_versions()
        except BaseException as exc:  # noqa: BLE001 — the assertion reports every worker
            errors.append(exc)

    workers = [threading.Thread(target=boot) for _ in range(4)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join()
    assert errors == []
    versions = PostgresRepo(url, url).migration_versions()
    assert "006_sandbox.sql" in versions
    assert "006_webhook.sql" in versions


def test_every_all_query_passes_params():
    import ast
    from pathlib import Path

    source = (Path(__file__).resolve().parents[1] / "kata_service" / "bureau_pg.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    missing = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr != "_all":
            continue
        if len(node.args) + len(node.keywords) < 2:
            missing.append(node.lineno)
    assert missing == []


def test_register_report_and_attest_on_postgres():
    from tests.test_bureau import _action, _agreement, _auth, _client, _key, _org, _register

    url = _database_url()
    _reset(url)
    client = _client(database_url=url, schema_url=url)
    operator = _org(client, "Harbor Agents", "agent_operator")
    merchant = _org(client, "Techstore", "merchant")
    wallet = _org(client, "Northwind Wallet", "wallet")
    operator_key = _key(client, operator["org_id"])
    merchant_key = _key(client, merchant["org_id"])
    wallet_key = _key(client, wallet["org_id"])
    registered = _register(client, operator_key)
    assert registered["agent_id"] == "shopper-01"
    stored = client.post(
        "/v1/agents/shopper-01/intents",
        headers={**_auth(operator_key), "Content-Type": "application/json"},
        content=_agreement().to_json(),
    )
    assert stored.status_code == 200, stored.text
    allowed = client.post(
        "/v1/verify",
        headers=_auth(merchant_key),
        json={"agent_id": "shopper-01", "action": _action(10, "act_report")},
    )
    assert allowed.status_code == 200, allowed.text
    assert allowed.json()["verdict"] == "ALLOW"
    evidence = "sha256:" + "ab" * 32
    filed = client.post(
        "/v1/reports",
        headers=_auth(merchant_key),
        json={
            "agent_id": "shopper-01",
            "kind": "fraud_incident",
            "evidence_hash": evidence,
            "summary": "Disputed charge",
        },
    )
    assert filed.status_code == 200, filed.text
    attested = client.post("/v1/agents/shopper-01/attest", headers=_auth(wallet_key))
    assert attested.status_code == 200, attested.text
    assert attested.json()["verification_level"] == "institution_attested"
