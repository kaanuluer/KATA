# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""One Postgres connection pool per process and database URL.

Uvicorn workers do not share a pool. Each worker opens its own, capped by
GAB_DB_POOL_MAX (default 10).
"""

from __future__ import annotations

import os
import threading

_pools: dict[str, object] = {}
_guard = threading.Lock()


def pool_max() -> int:
    raw = os.environ.get("GAB_DB_POOL_MAX")
    if not raw:
        return 10
    try:
        value = int(raw)
    except ValueError:
        return 10
    return min(max(value, 1), 50)


def pool_for(url: str):
    with _guard:
        pool = _pools.get(url)
        if pool is None:
            from psycopg_pool import ConnectionPool

            pool = ConnectionPool(
                url,
                min_size=0,
                max_size=pool_max(),
                timeout=5,
                max_idle=30,
                open=True,
                check=ConnectionPool.check_connection,
                kwargs={"connect_timeout": 3},
            )
            _pools[url] = pool
        return pool


def connection(url: str):
    """Context manager for a pooled connection. The caller commits by leaving the block."""

    return pool_for(url).connection()
