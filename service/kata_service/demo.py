# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: Apache-2.0
"""Sample intent the web page can sign and check. The seeds are public demo material."""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any

from kata_intent import Actor, Agreement, evaluate, private_key_from_seed
from kata_intent.errors import KataError
from kata_intent.values import as_time, money

_CURRENCY = re.compile(r"^[A-Z]{3}$")
_DAY = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def demo_keys():
    """Public demo keys. They are not a principal's production key."""

    principal = private_key_from_seed(hashlib.sha256(b"kata-demo-principal").digest())
    agent = private_key_from_seed(hashlib.sha256(b"kata-demo-agent").digest())
    return principal, agent


def run_demo(body: dict[str, Any], now: datetime | None = None) -> dict[str, Any]:
    """Sign one sample agreement and evaluate one payment against it."""

    if not isinstance(body, dict):
        raise ValueError("demo body must be an object")
    intent_in = body.get("intent") if isinstance(body.get("intent"), dict) else {}
    payment_in = body.get("payment") if isinstance(body.get("payment"), dict) else {}
    stamped = now or datetime.now(timezone.utc)
    at = as_time(stamped)

    maximum = _amount(intent_in.get("maximum_amount", 1500), "maximum amount")
    payment_amount = _amount(payment_in.get("amount", 1300), "payment amount")
    intent_currency = _currency(intent_in.get("currency") or "CAD", "intent currency")
    payment_currency = _currency(payment_in.get("currency") or intent_currency, "payment currency")
    purpose = _text(intent_in.get("purpose") or "purchase", "purpose")
    category = _optional_text(intent_in.get("category"))
    merchant = _optional_text(intent_in.get("merchant"))
    payment_merchant = _text(payment_in.get("merchant") or "techstore.example", "merchant")
    item = _text(payment_in.get("item") or "Laptop", "item")
    source = _optional_text(intent_in.get("natural_language")) or (
        f"Find and buy a laptop for me, maximum {maximum} {intent_currency}."
    )
    include_expiry = intent_in.get("include_expiry", True)
    if isinstance(include_expiry, str):
        include_expiry = include_expiry.strip().lower() not in {"", "0", "false", "no"}

    intent: dict[str, Any] = {
        "allowed_actions": ["search", "compare", "purchase"],
        "currency": intent_currency,
        "intent_id": "int_demo",
        "maximum_amount": maximum,
        "merchant_constraints": [merchant] if merchant else [],
        "natural_language_source": source,
        "purpose": purpose,
        "version": 1,
    }
    if category:
        intent["category"] = category
    expires_at = None
    if include_expiry:
        expires_at = _expiry(intent_in.get("time_limit"), stamped)
        intent["time_limit"] = expires_at

    principal, agent = demo_keys()
    agreement = Agreement.propose(
        agreement_id="agr_demo",
        principal={"display_name": "K. Uluer", "id": "usr_9182", "type": "human"},
        agent={"agent_id": "shopper-01"},
        agent_public_key=agent.public,
        delegation_id="dlg_demo",
        intent=intent,
        not_before=at,
        expires_at=expires_at,
        actor=Actor("agent", "shopper-01"),
        at=at,
        note="Sample drafted on the KATA page.",
    )
    preview = agreement.rendering_preview()
    try:
        agreement.accept(principal, at, confirmed_text=preview)
    except KataError as exc:
        raise ValueError(str(exc)) from exc

    action = {
        "action_id": "act_demo",
        "action_type": "purchase",
        "amount": payment_amount,
        "context": {"merchant": payment_merchant},
        "currency": payment_currency,
        "item": item,
        "parameters": {"merchant": payment_merchant, "quantity": 1},
        "proposed_at": at,
    }
    if category:
        action["context"]["category"] = category
        action["parameters"]["category"] = category
    try:
        result = evaluate(
            agreement,
            action,
            principal_public_key=principal.public,
            agent_id="shopper-01",
            agent_public_key=agent.public,
            now=at,
            ledger_sequence=agreement.ledger_sequence,
            ledger_head=agreement.ledger_head,
            ledger_as_of=at,
        )
    except KataError as exc:
        raise ValueError(str(exc)) from exc

    return {
        "agent_id": "shopper-01",
        "agreement_id": agreement.agreement_id,
        "confirmation_text": preview,
        "demo": True,
        "kata_decision": result.kata_decision,
        "mandate_hash": result.mandate_hash,
        "messages": list(result.messages),
        "principal": "K. Uluer",
        "principal_fingerprint": principal.public.fingerprint,
        "reasons": list(result.reasons),
        "required_action": result.required_action,
        "status": agreement.status,
        "verdict": result.verdict,
    }


def _amount(value: Any, label: str) -> Decimal:
    try:
        amount = money(value)
    except (KataError, TypeError, ValueError) as exc:
        raise ValueError(f"{label} must be a number") from exc
    if amount <= 0:
        raise ValueError(f"{label} must be greater than zero")
    return amount


def _currency(value: Any, label: str) -> str:
    text = str(value or "").strip().upper()
    if not _CURRENCY.match(text):
        raise ValueError(f"{label} is a three-letter code")
    return text


def _text(value: Any, label: str) -> str:
    text = str(value or "").strip()
    if not text or len(text) > 240:
        raise ValueError(f"{label} must be a short phrase")
    return text


def _optional_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if len(text) > 400:
        raise ValueError("text is too long")
    return text


def _expiry(value: Any, now: datetime) -> str:
    if value is None or str(value).strip() == "":
        return as_time(now + timedelta(days=30))
    text = str(value).strip()
    if _DAY.match(text):
        text = f"{text}T23:59:59Z"
    elif text.endswith("Z") or "+" in text[10:]:
        pass
    else:
        text = text + "Z" if "T" in text else f"{text}T23:59:59Z"
    try:
        return as_time(text)
    except KataError as exc:
        raise ValueError("expiry must be a date or a UTC timestamp") from exc
