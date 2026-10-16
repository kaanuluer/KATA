# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Turn a UCP checkout into a KATA action.

Verified rules come from docs/ucp-research.md. Field paths that the note does
not verify live in adapters/ucp/checkout.v1.json and stay marked assumed.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Any

_REVERSE_DOMAIN = re.compile(r"^[a-z0-9_]+(?:-[a-z0-9_]+)*(?:\.[a-z0-9_]+(?:-[a-z0-9_]+)*)+$")
_CURRENCY = re.compile(r"^[A-Z]{3}$")
_KNOWN = frozenset({"totals", "currency", "id", "signals", "context", "ap2", "ucp"})


class CheckoutRejected(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


@dataclass(frozen=True)
class Translation:
    action: dict[str, Any] | None
    deny_code: str | None
    deny_message: str | None
    report: dict[str, Any]


def config_path() -> Path:
    here = Path(__file__).resolve()
    for candidate in (Path.cwd(), *here.parents):
        path = candidate / "adapters" / "ucp" / "checkout.v1.json"
        if path.is_file():
            return path
    raise CheckoutRejected(500, "ucp checkout config was not found")


def load_config(path: Path | None = None) -> dict[str, Any]:
    chosen = path or config_path()
    document = json.loads(chosen.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise CheckoutRejected(500, "ucp checkout config was not found")
    return document


def translate_checkout(checkout: dict[str, Any], *, at: str, config: dict[str, Any] | None = None) -> Translation:
    """Map one checkout. Signal values are never copied into the action."""

    spec = config or load_config()
    version = str(spec.get("ucp_version") or "")
    fields: list[dict[str, str]] = []
    _version(checkout, version, fields)
    deny = _signals(checkout, fields)
    _context(checkout, fields)
    _ap2(checkout, fields)
    amount, currency, action_id = None, None, "ucp-checkout"
    if deny is None:
        amount_bits = _amount(checkout, spec, fields)
        if isinstance(amount_bits, tuple) and amount_bits[0] == "deny":
            deny = (str(amount_bits[1]), str(amount_bits[2]))
        elif isinstance(amount_bits, tuple):
            amount, currency, action_id = amount_bits
    report = {
        "schema_version": spec.get("schema_version"),
        "ucp_version": version,
        "compatibility_claim": "none",
        "hosts_checkout": False,
        "fields": fields,
        "unmapped": _unmapped(checkout),
        "preserved": checkout,
    }
    if deny is not None:
        return Translation(None, deny[0], deny[1], report)
    assert amount is not None and currency is not None
    report["action"] = {"action_id": action_id, "action_type": "purchase", "amount": amount, "currency": currency}
    action = {
        "action_id": action_id,
        "action_type": str((spec.get("action_type") or {}).get("value") or "purchase"),
        "amount": amount,
        "currency": currency,
        "proposed_at": at,
        "context": {"protocol": "UCP", "ucp_version": version},
        "parameters": {},
    }
    return Translation(action, None, None, report)


def _version(checkout: dict[str, Any], expected: str, fields: list[dict[str, str]]) -> None:
    ucp = checkout.get("ucp")
    if not isinstance(ucp, dict) or "version" not in ucp:
        fields.append({"name": "ucp.version", "status": "verified", "disposition": "absent"})
        return
    if ucp.get("version") != expected:
        raise CheckoutRejected(400, "ucp.version is not 2026-08-25")
    fields.append({"name": "ucp.version", "status": "verified", "disposition": "matched"})


def _signals(checkout: dict[str, Any], fields: list[dict[str, str]]) -> tuple[str, str] | None:
    buyer = checkout.get("buyer")
    if isinstance(buyer, dict) and "signals" in buyer:
        fields.append({"name": "buyer.signals", "status": "verified", "disposition": "rejected"})
        return ("BUYER_ASSERTED_SIGNAL", "Checkout signals must not be buyer-asserted.")
    context = checkout.get("context")
    if isinstance(context, dict) and "signals" in context:
        fields.append({"name": "context.signals", "status": "verified", "disposition": "rejected"})
        return ("BUYER_ASSERTED_SIGNAL", "Checkout signals must not be buyer-asserted.")
    if "signals" not in checkout:
        fields.append({"name": "signals", "status": "verified", "disposition": "absent"})
        return None
    signals = checkout.get("signals")
    if not isinstance(signals, dict):
        raise CheckoutRejected(400, "signals must be an object")
    for key, value in signals.items():
        if not isinstance(key, str) or not _REVERSE_DOMAIN.match(key):
            raise CheckoutRejected(400, "signal key must be a reverse-domain name")
        if _buyer_value(value):
            fields.append({"name": f"signals.{key}", "status": "verified", "disposition": "rejected"})
            return ("BUYER_ASSERTED_SIGNAL", "Checkout signals must not be buyer-asserted.")
        fields.append({"name": f"signals.{key}", "status": "verified", "disposition": "ignored"})
    return None


def _buyer_value(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    source = str(value.get("source") or value.get("asserted_by") or "").strip().lower()
    return source == "buyer" or value.get("buyer_asserted") is True


def _context(checkout: dict[str, Any], fields: list[dict[str, str]]) -> None:
    if "context" not in checkout:
        fields.append({"name": "context", "status": "verified", "disposition": "absent"})
        return
    fields.append({"name": "context", "status": "verified", "disposition": "provisional"})


def _ap2(checkout: dict[str, Any], fields: list[dict[str, str]]) -> None:
    ap2 = checkout.get("ap2")
    if not isinstance(ap2, dict):
        fields.append({"name": "ap2.checkout_mandate", "status": "verified", "disposition": "absent"})
        return
    if "checkout_mandate" in ap2:
        fields.append({"name": "ap2.checkout_mandate", "status": "verified", "disposition": "not a grant"})
    else:
        fields.append({"name": "ap2.checkout_mandate", "status": "verified", "disposition": "absent"})
    if "merchant_authorization" in ap2:
        fields.append({"name": "ap2.merchant_authorization", "status": "verified", "disposition": "not a grant"})


def _amount(
    checkout: dict[str, Any], spec: dict[str, Any], fields: list[dict[str, str]]
) -> tuple[Any, ...] | tuple[str, str, str]:
    amount_spec = spec.get("amount") or {}
    currency_spec = spec.get("currency") or {}
    totals = checkout.get(str(amount_spec.get("path") or "totals"))
    if not isinstance(totals, list):
        fields.append({"name": "totals", "status": "assumed", "disposition": "missing"})
        return ("deny", "CHECKOUT_TOTAL_UNMAPPED", "The checkout has no assumed total in minor units.")
    type_field = str(amount_spec.get("type_field") or "type")
    type_value = amount_spec.get("type_value")
    amount_field = str(amount_spec.get("amount_field") or "amount")
    chosen = [item for item in totals if isinstance(item, dict) and item.get(type_field) == type_value]
    if len(chosen) > 1:
        fields.append({"name": "totals", "status": "assumed", "disposition": "ambiguous"})
        return ("deny", "CHECKOUT_TOTAL_AMBIGUOUS", "The checkout has more than one total.")
    if len(chosen) != 1 or amount_field not in chosen[0]:
        fields.append({"name": "totals", "status": "assumed", "disposition": "missing"})
        return ("deny", "CHECKOUT_TOTAL_UNMAPPED", "The checkout has no assumed total in minor units.")
    raw = chosen[0][amount_field]
    if isinstance(raw, bool) or not isinstance(raw, int):
        fields.append({"name": "totals.amount", "status": "assumed", "disposition": "not minor units"})
        return ("deny", "CHECKOUT_AMOUNT_NOT_MINOR", "The checkout total must be an integer in minor units.")
    currency_path = str(currency_spec.get("path") or "currency")
    currency = checkout.get(currency_path)
    if not isinstance(currency, str) or not _CURRENCY.match(currency):
        fields.append({"name": "currency", "status": "assumed", "disposition": "missing"})
        return ("deny", "CHECKOUT_CURRENCY_UNMAPPED", "The checkout has no assumed currency.")
    scales = (spec.get("currency_scale") or {}).get("exponents") or {}
    exponent = scales.get(currency)
    if not isinstance(exponent, int) or isinstance(exponent, bool) or exponent < 0:
        fields.append({"name": "currency_scale", "status": "assumed", "disposition": "unknown"})
        return ("deny", "CHECKOUT_CURRENCY_SCALE_UNKNOWN", "The minor-unit scale for this currency is not in the assumed table.")
    major = Decimal(raw) / (Decimal(10) ** exponent)
    amount: int | str = int(major) if major == major.to_integral_value() else format(major, "f")
    fields.append({"name": "totals.amount", "status": "assumed", "disposition": "used"})
    fields.append({"name": "currency", "status": "assumed", "disposition": "used"})
    fields.append({"name": "currency_scale", "status": "assumed", "disposition": "used"})
    action_id = _action_id(checkout, spec, fields)
    return (amount, currency, action_id)


def _action_id(checkout: dict[str, Any], spec: dict[str, Any], fields: list[dict[str, str]]) -> str:
    path = str((spec.get("id") or {}).get("path") or "id")
    value = checkout.get(path)
    if isinstance(value, str) and 1 <= len(value) <= 80:
        fields.append({"name": "id", "status": "assumed", "disposition": "used"})
        return value
    fields.append({"name": "id", "status": "assumed", "disposition": "default"})
    return "ucp-checkout"


def _unmapped(checkout: dict[str, Any]) -> list[str]:
    return sorted(str(key) for key in checkout if str(key) not in _KNOWN)
