# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Row hash chain for gab_audit.

The first row's prev_hash is the start node. Each later row names the previous
row's hash. This is tamper-evident: a changed row or a broken link shows up
when the chain is checked. It is not a claim about the database host.
"""

from __future__ import annotations

from typing import Any

from kata_intent.values import hash_document

# Start node. It is not a row. The earliest row's prev_hash is this value.
AUDIT_CHAIN_START = "start"


def audit_stored_fields(record: dict[str, Any]) -> dict[str, Any]:
    """The columns covered by the row hash, aside from prev_hash and hash."""

    environment = record.get("environment")
    return {
        "agent_id": record.get("agent_id"),
        "at": record["at"],
        "audit_id": record["audit_id"],
        "environment": environment if environment == "test" else "live",
        "key_id": record.get("key_id"),
        "method": record["method"],
        "org_id": record.get("org_id"),
        "path": record["path"],
        "purpose_code": record.get("purpose_code"),
        "status": int(record["status"]),
    }


def audit_row_hash(prev_hash: str, record: dict[str, Any]) -> str:
    body = audit_stored_fields(record)
    body["prev_hash"] = prev_hash
    return hash_document(body)


def verify_audit_chain(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Walk the chain from the start node.

    ``ok`` is false when a prev_hash does not link or a hash does not match
    the stored columns. The result names the row where the check stopped.
    """

    if not rows:
        return {"ok": True, "rows": 0, "start": AUDIT_CHAIN_START}
    by_prev: dict[str, dict[str, Any]] = {}
    for row in rows:
        prev = row.get("prev_hash")
        if not isinstance(prev, str) or prev in by_prev:
            return {
                "ok": False,
                "rows": len(rows),
                "start": AUDIT_CHAIN_START,
                "audit_id": row.get("audit_id"),
                "break": "prev_hash is missing or repeated",
            }
        by_prev[prev] = row
    if AUDIT_CHAIN_START not in by_prev:
        return {
            "ok": False,
            "rows": len(rows),
            "start": AUDIT_CHAIN_START,
            "break": "start node is missing",
        }
    seen = 0
    prev = AUDIT_CHAIN_START
    while prev in by_prev:
        row = by_prev.pop(prev)
        expected = audit_row_hash(str(row["prev_hash"]), row)
        if row.get("hash") != expected:
            return {
                "ok": False,
                "rows": len(rows),
                "start": AUDIT_CHAIN_START,
                "audit_id": row.get("audit_id"),
                "break": "hash does not match the row",
            }
        seen += 1
        prev = str(row["hash"])
    if by_prev:
        orphan = next(iter(by_prev.values()))
        return {
            "ok": False,
            "rows": len(rows),
            "start": AUDIT_CHAIN_START,
            "audit_id": orphan.get("audit_id"),
            "break": "row is not linked from the start node",
        }
    return {"ok": True, "rows": seen, "start": AUDIT_CHAIN_START}
