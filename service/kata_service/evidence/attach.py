# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Record evidence next to a KATA decision without changing that decision.

The verify response is left as the caller built it. The evidence row points at
that decision. It does not replace it.
"""

from __future__ import annotations

import secrets
from contextvars import ContextVar
from typing import Any

from kata_service.evidence.schema import empty_hash, evidence_object
from kata_service.evidence.store import EvidenceStore, MemoryEvidenceStore, PostgresEvidenceStore
from kata_service.evidence.verifier import utc_seconds, verifier_for

_evidence_id: ContextVar[str | None] = ContextVar("gab_evidence_id", default=None)


def clear_evidence_id() -> None:
    _evidence_id.set(None)


def take_evidence_id() -> str | None:
    value = _evidence_id.get()
    _evidence_id.set(None)
    return value


def store_for(bureau: Any) -> EvidenceStore:
    existing = getattr(bureau, "_evidence_store", None)
    if existing is not None:
        return existing
    url = getattr(getattr(bureau, "repo", None), "database_url", None)
    store: EvidenceStore
    if isinstance(url, str) and url:
        store = PostgresEvidenceStore(url)
    else:
        store = MemoryEvidenceStore()
    bureau._evidence_store = store
    return store


def decision_ref(body: dict[str, Any], payload: dict[str, Any]) -> str:
    action = body.get("action") if isinstance(body.get("action"), dict) else {}
    action_id = action.get("action_id") if isinstance(action.get("action_id"), str) else ""
    parts = (
        str(payload.get("agent_id") or ""),
        str(payload.get("agreement_id") or ""),
        action_id,
        str(payload.get("kata_decision") or ""),
    )
    return "|".join(parts)


def record_external_evidence(bureau: Any, body: dict[str, Any], payload: dict[str, Any]) -> None:
    """Verify ``external_evidence`` and store the result. ``payload`` is not modified."""

    if not isinstance(body, dict) or "external_evidence" not in body:
        return
    material = body.get("external_evidence")
    moment = utc_seconds(bureau.now())
    stamp = moment.strftime("%Y-%m-%dT%H:%M:%SZ")
    store = store_for(bureau)
    if not isinstance(material, dict):
        evidence = evidence_object(
            source="unknown",
            verified_at=stamp,
            result="unverifiable",
            reason="malformed",
            payload_hash_hex=empty_hash(),
        )
    else:
        source = material.get("source")
        verifier = verifier_for(source if isinstance(source, str) else "", store)
        evidence = verifier.verify(material, now=moment)
    action = body.get("action") if isinstance(body.get("action"), dict) else {}
    action_id = action.get("action_id") if isinstance(action.get("action_id"), str) else None
    evidence_id = "ev_" + secrets.token_hex(8)
    store.save_evidence(
        {
            "evidence_id": evidence_id,
            "evidence": evidence,
            "decision_ref": decision_ref(body, payload),
            "agent_id": payload.get("agent_id") if isinstance(payload.get("agent_id"), str) else None,
            "agreement_id": payload.get("agreement_id") if isinstance(payload.get("agreement_id"), str) else None,
            "action_id": action_id,
            "kata_decision": payload.get("kata_decision") if isinstance(payload.get("kata_decision"), str) else None,
            "audit_id": None,
            "created_at": stamp,
        }
    )
    _evidence_id.set(evidence_id)


def link_audit(bureau: Any, evidence_id: str, audit_id: str) -> None:
    store_for(bureau).link_audit(evidence_id, audit_id)
