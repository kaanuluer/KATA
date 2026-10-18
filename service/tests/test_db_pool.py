# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Postgres queries borrow from the process pool. SYNTHETIC TEST DATA."""

from __future__ import annotations

from kata_service.bureau_pg import PostgresRepo
from kata_service.db_pool import pool_for, pool_max
from tests.test_postgres_path import _database_url, _reset


def test_pool_max_defaults_and_caps(monkeypatch):
    monkeypatch.delenv("GAB_DB_POOL_MAX", raising=False)
    assert pool_max() == 10
    monkeypatch.setenv("GAB_DB_POOL_MAX", "4")
    assert pool_max() == 4
    monkeypatch.setenv("GAB_DB_POOL_MAX", "nope")
    assert pool_max() == 10
    monkeypatch.setenv("GAB_DB_POOL_MAX", "80")
    assert pool_max() == 50


def test_repo_borrows_a_pooled_connection():
    url = _database_url()
    _reset(url)
    repo = PostgresRepo(url, url)
    assert "001_bureau.sql" in repo.migration_versions()
    pool = pool_for(url)
    assert pool.max_size >= 1
    with repo._connect() as conn:
        assert conn.execute("SELECT 1").fetchone()[0] == 1
    with repo._connect() as conn:
        assert conn.execute("SELECT 1").fetchone()[0] == 1
