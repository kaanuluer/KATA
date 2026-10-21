# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Entity-only request checks.

The flag defaults off. Turning it on rejects unknown fields on verify, report,
and dispute, rejects an email or phone pattern in the free-text fields of those
requests, and requires a caller-attested entity_kind of business or personal.
That attestation is stored as the caller sent it.

Network-signal reasons can be downgraded from DENY to STEP_UP when that separate
flag is on. Mandate failures and velocity reasons stay DENY. Default off, because
the downgrade changes which checks stop a payment.

This module does not claim legal compliance or certification.
"""

from __future__ import annotations

import re
from typing import Any

ENTITY_KINDS = ("business", "personal")
VERIFY_FIELDS = frozenset({"agent_id", "action", "agreement_id", "intent_id", "counterparty_org_id"})
REPORT_FIELDS = frozenset({"agent_id", "kind", "evidence_hash", "summary", "outcome", "action_id", "shared_signal"})
DISPUTE_FIELDS = frozenset({"report_id", "statement", "assertion"})
_PERSON_KEYS = frozenset({"principal_id", "principal", "principal_email", "email", "history"})
NETWORK_SIGNAL_REASONS = frozenset(
    {"NETWORK_SIGNAL", "DEVICE_SIGNAL", "KEY_SIGNAL", "IP_SIGNAL", "TIMING_SIGNAL"}
)
_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_PHONE = re.compile(r"(?:\+\d{8,15})|(?:\b\d{3}[-. )]\d{3}[-. ]\d{4}\b)")


def entity_kind(value: Any, *, required: bool) -> str | None:
    if value is None or value == "":
        if required:
            _fail(400, "entity_kind must be business or personal")
        return None
    text = str(value).strip().lower()
    if text not in ENTITY_KINDS:
        _fail(400, "entity_kind must be business or personal")
    return text


def screen_request(kind: str, body: dict[str, Any]) -> None:
    allowed = {"verify": VERIFY_FIELDS, "report": REPORT_FIELDS, "dispute": DISPUTE_FIELDS}[kind]
    unknown = sorted(set(body) - allowed)
    if unknown:
        _fail(400, "unknown field")
    if kind == "verify":
        _reject_personal(body.get("action"))
    elif kind == "report":
        _reject_personal(body.get("summary"))
        _reject_personal(body.get("shared_signal"))
    else:
        _reject_personal(body.get("statement"))


def strip_person(payload: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in payload.items() if key not in _PERSON_KEYS}


def downgrade_network_deny(payload: dict[str, Any]) -> dict[str, Any]:
    if payload.get("verdict") != "DENY":
        return payload
    reasons = [str(item) for item in payload.get("reasons") or []]
    if not reasons or set(reasons) - NETWORK_SIGNAL_REASONS:
        return payload
    updated = dict(payload)
    updated["verdict"] = "STEP_UP"
    updated["kata_decision"] = "STEP_UP"
    updated["reasons"] = [*reasons, "NETWORK_SIGNAL_STEP_UP"]
    return updated


def _reject_personal(value: Any) -> None:
    if isinstance(value, str):
        if _EMAIL.search(value) or _PHONE.search(value):
            _fail(400, "free text must not contain an email or phone number")
        return
    if isinstance(value, dict):
        for item in value.values():
            _reject_personal(item)
        return
    if isinstance(value, list):
        for item in value:
            _reject_personal(item)


def reject_contact_text(value: Any) -> None:
    _reject_personal(value)


def _fail(status: int, message: str) -> None:
    from kata_service.bureau import BureauError

    raise BureauError(status, message)
