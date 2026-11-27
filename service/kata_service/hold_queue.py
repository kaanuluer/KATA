# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Human approval queue for one STEP_UP verify.

GAB_HOLD_QUEUE defaults off. This is an approval queue, not case management.
A hold stores the original decision_ref and payload hash. An approval can be
used once, and only with that same amount, payee, and payload. A missing
gab_holds table is not an error: the caller keeps today's decision. A store
error becomes STEP_UP with HOLD_UNAVAILABLE and never ALLOW.
"""

from __future__ import annotations

import re
from typing import Any

from kata_intent.errors import KataError
from kata_intent.values import hash_document, money

from kata_service.evidence.attach import decision_ref

REASON_EXPIRED = "HOLD_EXPIRED"
REASON_UNAVAILABLE = "HOLD_UNAVAILABLE"
EXPIRED_MESSAGE = "The hold expired."
UNAVAILABLE_MESSAGE = "The hold queue could not be written."
NOT_AVAILABLE = "not available"

# A human approval covers only these step-up reasons. Stop, authority ceilings,
# intent limits, and cumulative spend are checked again and are not waived.
WAIVABLE_STEP_UP = frozenset({"AUTHORITY_STEP_UP", "AUTHORITY_APPROVAL_REQUIRED"})

_REVIEWER = re.compile(r"^[A-Za-z0-9._:@-]{1,80}$")
_HOLD_ID = re.compile(r"^[A-Za-z0-9_-]{1,80}$")
_PAYEE_KEYS = ("payee", "recipient", "merchant", "counterparty")


class HoldTableMissing(Exception):
    """gab_holds is not present. Callers keep today's decision."""


class HoldStoreError(Exception):
    """The hold store failed for a reason other than a missing table."""


def reviewer_text(value: Any) -> str | None:
    """Return a reviewer id, or None when the value is not usable."""

    if not isinstance(value, str):
        return None
    text = value.strip()
    if _REVIEWER.fullmatch(text) is None:
        return None
    return text


def reason_text(value: Any) -> str | None:
    """Return a review reason, or None when the value is not usable."""

    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text or len(text) > 500:
        return None
    if any(ord(char) < 32 or ord(char) == 127 for char in text):
        return None
    return text


def hold_id_text(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    if _HOLD_ID.fullmatch(text) is None:
        return None
    return text


def amount_text(action: Any) -> str:
    if not isinstance(action, dict) or "amount" not in action:
        return ""
    try:
        number = money(action.get("amount"))
    except (KataError, TypeError, ValueError):
        return ""
    if number < 0:
        return ""
    if number == number.to_integral_value():
        return str(int(number))
    return format(number, "f")


def payee_of(action: Any) -> str:
    """The payee the approval is bound to. A missing payee is an empty string."""

    if not isinstance(action, dict):
        return ""
    found = _named(_PAYEE_KEYS, action)
    if found:
        return found
    for container_name in ("context", "parameters"):
        found = _named(_PAYEE_KEYS, action.get(container_name))
        if found:
            return found
    return ""


def payload_hash_for(body: dict[str, Any], agreement_id: str) -> str:
    action = body.get("action") if isinstance(body.get("action"), dict) else {}
    intent = body.get("intent_id") if isinstance(body.get("intent_id"), str) else ""
    material = {
        "action": action,
        "agent_id": str(body.get("agent_id") or ""),
        "agreement_id": agreement_id,
        "intent_id": intent,
    }
    return hash_document(material)


def bound_decision_ref(body: dict[str, Any], agreement_id: str, kata_decision: str) -> str:
    return decision_ref(
        body,
        {
            "agent_id": str(body.get("agent_id") or ""),
            "agreement_id": agreement_id,
            "kata_decision": kata_decision,
        },
    )


def binding_failure(hold: dict[str, Any], body: dict[str, Any]) -> str | None:
    """Return which binding failed, or None when the request matches the hold.

    Amount, payee, and any other payload change are separate failures. A
    different action id changes decision_ref.
    """

    action = body.get("action") if isinstance(body.get("action"), dict) else {}
    agreement_id = str(hold.get("agreement_id") or "")
    kata_decision = str(hold.get("kata_decision") or "STEP_UP")
    if amount_text(action) != str(hold.get("amount") or ""):
        return "amount"
    if payee_of(action) != str(hold.get("payee") or ""):
        return "payee"
    if payload_hash_for(body, agreement_id) != hold.get("payload_hash"):
        return "payload"
    if bound_decision_ref(body, agreement_id, kata_decision) != hold.get("decision_ref"):
        return "decision_ref"
    return None


def waived_release(payload: dict[str, Any]) -> dict[str, Any] | None:
    """Return ALLOW when a human approval covers this step-up. Otherwise None.

    Stop, observe-only, ceilings, and limit denials are not waived.
    """

    if not isinstance(payload, dict) or payload.get("verdict") != "STEP_UP":
        return None
    reasons = payload.get("reasons") or []
    if not isinstance(reasons, list) or not reasons:
        return None
    if any(not isinstance(code, str) or code not in WAIVABLE_STEP_UP for code in reasons):
        return None
    updated = dict(payload)
    updated["verdict"] = "ALLOW"
    updated["kata_decision"] = "ALLOW"
    updated["reasons"] = []
    updated["messages"] = []
    updated["required_action"] = "NONE"
    return updated


def hold_unavailable_decision(payload: dict[str, Any] | None) -> dict[str, Any]:
    """STEP_UP with HOLD_UNAVAILABLE. The verdict is never ALLOW."""

    updated = dict(payload) if isinstance(payload, dict) else {}
    reasons = [
        code
        for code in list(updated.get("reasons") or [])
        if isinstance(code, str) and code != REASON_UNAVAILABLE
    ]
    messages = [
        text
        for text in list(updated.get("messages") or [])
        if isinstance(text, str) and text != UNAVAILABLE_MESSAGE
    ]
    updated["verdict"] = "STEP_UP"
    updated["kata_decision"] = "STEP_UP"
    updated["reasons"] = [REASON_UNAVAILABLE, *reasons]
    updated["messages"] = [UNAVAILABLE_MESSAGE, *messages]
    updated["required_action"] = "HUMAN_APPROVAL"
    return updated


def hold_expired_decision(payload: dict[str, Any] | None) -> dict[str, Any]:
    """DENY with HOLD_EXPIRED. The verdict is never ALLOW."""

    updated = dict(payload) if isinstance(payload, dict) else {}
    updated["verdict"] = "DENY"
    updated["kata_decision"] = "BLOCK"
    updated["reasons"] = [REASON_EXPIRED]
    updated["messages"] = [EXPIRED_MESSAGE]
    updated["required_action"] = "NONE"
    return updated


def closed_step_up(payload: dict[str, Any]) -> dict[str, Any]:
    """A step-up that a release could not re-check becomes DENY, not ALLOW."""

    updated = dict(payload)
    updated["verdict"] = "DENY"
    updated["kata_decision"] = "BLOCK"
    updated["required_action"] = "NONE"
    return updated


def public_hold(hold: dict[str, Any]) -> dict[str, Any]:
    view = {
        "hold_id": hold["hold_id"],
        "agent_id": hold.get("agent_id"),
        "agreement_id": hold.get("agreement_id") or "",
        "decision_ref": hold.get("decision_ref"),
        "payload_hash": hold.get("payload_hash"),
        "amount": hold.get("amount") or "",
        "currency": hold.get("currency") or "",
        "payee": hold.get("payee") or "",
        "status": hold.get("status"),
        "expires_at": hold.get("expires_at"),
        "created_at": hold.get("created_at"),
    }
    if hold.get("reviewer_id"):
        view["reviewer_id"] = hold["reviewer_id"]
    if hold.get("decision_reason"):
        view["reason"] = hold["decision_reason"]
    if hold.get("decided_at"):
        view["decided_at"] = hold["decided_at"]
    return view


def _named(keys: tuple[str, ...], container: Any) -> str:
    if not isinstance(container, dict):
        return ""
    for key in keys:
        value = container.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""
