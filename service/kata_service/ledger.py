# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Ledger body allow-list and detached payload encryption.

The chain keeps identifiers, hashes, and timestamps. A payload object is
envelope-encrypted and the wrapped data key is stored outside the row. Erasure
destroys that data key. The chain entry stays so verification still works.
A correction is a new entry. Old entries are not rewritten.

This module does not claim legal compliance or certification.
"""

from __future__ import annotations

import secrets
from typing import Any, Callable

from kata_intent.canonical import canonical_bytes
from kata_intent.values import hash_document

from kata_service.keys import seal_detached

_EXACT = frozenset(
    {
        "fingerprint",
        "status",
        "kind",
        "sequence",
        "currency",
        "payload_hash",
        "subject_ref",
        "corrects_sequence",
    }
)
_PI = frozenset(
    {
        "email",
        "phone",
        "name",
        "summary",
        "statement",
        "endpoint",
        "auth_secret",
        "ip",
        "address",
        "principal_email",
        "payload",
    }
)


class LedgerBodyError(ValueError):
    """The ledger body is not on the allow-list."""


def allowed_field(key: str) -> bool:
    if key in _PI or key.endswith("_email") or "password" in key:
        return False
    if key in _EXACT:
        return True
    return key.endswith("_id") or key.endswith("_hash") or key.endswith("_at") or key.endswith("_ref")


def check_body(body: dict[str, Any]) -> None:
    for key, value in body.items():
        if not allowed_field(key):
            raise LedgerBodyError("ledger body field is not allowed")
        if isinstance(value, (dict, list)):
            raise LedgerBodyError("ledger body values must be scalars")


def prepare_body(
    body: dict[str, Any],
    *,
    provider,
    dek_store,
    put_payload: Callable[[dict[str, Any]], None],
    at: str,
) -> dict[str, Any]:
    working = dict(body)
    payload = working.pop("payload", None)
    if "principal_id" in working:
        token = provider.hmac(str(working.pop("principal_id")), purpose="subject")
        working["subject_ref"] = token.encode()
    if payload is not None:
        if not isinstance(payload, dict):
            raise LedgerBodyError("ledger payload must be an object")
        subject = str(working.get("subject_ref") or working.get("agent_id") or "ledger")
        sealed, wrapped = seal_detached(provider, canonical_bytes(payload), subject_id=subject)
        dek_store.put(subject, wrapped)
        digest = hash_document(payload)
        put_payload(
            {
                "payload_id": "pay_" + secrets.token_hex(8),
                "subject_ref": subject,
                "payload_hash": digest,
                "ciphertext": sealed,
                "created_at": at,
            }
        )
        working["payload_hash"] = digest
    check_body(working)
    return working
