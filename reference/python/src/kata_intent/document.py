# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: Apache-2.0
"""The bytes a principal, a counterparty, or a revocation actually signs."""

from __future__ import annotations

from typing import Any

from kata_intent.values import coerce, hash_document

_PRINCIPAL_KEYS = ("display_name", "id", "public_key", "type")
_AGENT_KEYS = ("agent_id", "public_key", "public_key_fingerprint")
_OPTIONAL = (
    "delegation_id",
    "expires_at",
    "limits",
    "not_before",
    "parent_limits",
    "required_acknowledgements",
    "revocation_endpoint",
    "supersedes",
)


def core_document(mandate: dict[str, Any]) -> dict[str, Any]:
    """Fields common to the unsigned draft and the signed mandate."""

    mandate = coerce(mandate)
    document: dict[str, Any] = {
        "agent": _pick(mandate.get("agent") or {}, _AGENT_KEYS),
        "intent": mandate.get("intent") or {},
        "mandate_id": mandate.get("mandate_id"),
        "principal": _pick(mandate.get("principal") or {}, _PRINCIPAL_KEYS),
        "version": mandate.get("version"),
    }
    for key in _OPTIONAL:
        if key in mandate:
            document[key] = mandate[key]
    return document


def signing_document(mandate: dict[str, Any]) -> dict[str, Any]:
    """The object inside the mandate JWS payload."""

    document = core_document(mandate)
    rendering = mandate.get("rendering") or {}
    document["kata_mandate"] = "1"
    document["rendering"] = {"hash": rendering.get("hash"), "text": rendering.get("text")}
    return document


def draft_document(mandate: dict[str, Any]) -> dict[str, Any]:
    """Hash input for a draft that has not been signed yet."""

    document = core_document(mandate)
    document["kata_mandate_draft"] = "1"
    return document


def mandate_hash(mandate: dict[str, Any]) -> str:
    if mandate.get("signature") and mandate.get("rendering"):
        return hash_document(signing_document(mandate))
    return hash_document(draft_document(mandate))


def acknowledgement_document(ack: dict[str, Any]) -> dict[str, Any]:
    ack = coerce(ack)
    return {
        "agreement_id": ack.get("agreement_id"),
        "at": ack.get("at"),
        "id": ack.get("id"),
        "kata_ack": "1",
        "mandate_hash": ack.get("mandate_hash"),
        "public_key": ack.get("public_key"),
        "role": ack.get("role"),
    }


def revocation_document(revocation: dict[str, Any]) -> dict[str, Any]:
    revocation = coerce(revocation)
    document = {
        "agreement_id": revocation.get("agreement_id"),
        "at": revocation.get("at"),
        "kata_revocation": "1",
        "mandate_hash": revocation.get("mandate_hash"),
        "reason": revocation.get("reason"),
    }
    if revocation.get("mandate_hashes"):
        document["mandate_hashes"] = list(revocation["mandate_hashes"])
    return document


def _pick(source: dict[str, Any], keys: tuple[str, ...]) -> dict[str, Any]:
    return {key: source[key] for key in keys if key in source}
