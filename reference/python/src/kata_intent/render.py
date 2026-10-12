# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: Apache-2.0
"""Human-readable rendering of a mandate.

The text is part of what the principal signs (``kata_mandate`` version 1).
Verifiers recompute it from the structured fields. A mandate whose stored
rendering differs from this text does not verify.

The line order below is normative for version 1. Whitespace inside a quoted
instruction is collapsed, so a newline in the source cannot push the limits
out of a single-line display.
"""

from __future__ import annotations

from typing import Any

from kata_intent.canonical import encode_decimal
from kata_intent.values import money

MONEY_PURPOSES = frozenset({"purchase", "payment", "transfer", "booking", "investment"})

_FREQUENCY = {
    "agreement": "over the life of this agreement",
    "P1D": "per day",
    "P7D": "per 7 days",
    "P1M": "per 30 days",
}


def render_mandate(mandate: dict[str, Any]) -> str:
    """Return the confirmation text for ``mandate``."""

    intent = mandate.get("intent") or {}
    limits = mandate.get("limits") or {}
    principal = mandate.get("principal") or {}
    agent = mandate.get("agent") or {}
    lines: list[str] = []

    who = principal.get("id", "")
    display = principal.get("display_name")
    if display:
        who = f"{display}, {who}"
    purpose = intent.get("purpose", "act")
    lines.append(f"You ({who}) authorize agent {agent.get('agent_id', '')} to {purpose}.")

    fingerprint = agent.get("public_key_fingerprint")
    if fingerprint:
        lines.append(f"Agent key: {fingerprint}.")

    source = intent.get("natural_language_source")
    if isinstance(source, str) and source.strip():
        lines.append(f'Your words: "{_one_line(source)}".')

    amount = intent.get("maximum_amount")
    if amount is None:
        amount = limits.get("per_transaction_maximum")
    currency = intent.get("currency") or limits.get("currency") or ""
    if amount is not None:
        lines.append(f"Up to {_amount(amount)} {currency} per transaction.".rstrip())
    elif purpose in MONEY_PURPOSES:
        lines.append("No per-transaction amount limit is declared.")

    cumulative = limits.get("cumulative_maximum")
    if cumulative is not None:
        cumulative_currency = limits.get("currency") or currency
        lines.append(
            f"Up to {_amount(cumulative)} {cumulative_currency} in total under this agreement.".rstrip()
        )

    frequency = limits.get("frequency") or {}
    if frequency.get("max_count") is not None:
        phrase = _FREQUENCY.get(str(frequency.get("per")), str(frequency.get("per")))
        lines.append(f"At most {frequency['max_count']} times {phrase}.")

    category = intent.get("category")
    lines.append(f"Category: {category}." if category else "Category: any.")

    merchants = intent.get("merchant_constraints") or []
    if merchants:
        lines.append("Merchants allowed: " + ", ".join(str(item) for item in merchants) + ".")
    else:
        lines.append("Merchants allowed: any.")
    denied = limits.get("merchant_denylist") or []
    if denied:
        lines.append("Merchants refused: " + ", ".join(str(item) for item in denied) + ".")

    actions = intent.get("allowed_actions")
    if actions:
        lines.append("Allowed actions: " + ", ".join(str(item) for item in actions) + ".")
    else:
        lines.append("Allowed actions: any.")

    lines.append(_window_line(mandate.get("not_before"), mandate.get("expires_at") or intent.get("time_limit")))

    expectation = intent.get("price_expectation") or {}
    if expectation:
        bits = []
        if expectation.get("quoted_price") is not None:
            bits.append(f"quoted {_amount(expectation['quoted_price'])}")
        if expectation.get("listed_price") is not None:
            bits.append(f"listed {_amount(expectation['listed_price'])}")
        price_currency = expectation.get("currency") or currency
        tolerance = expectation.get("tolerance_ratio")
        tolerance_text = f", tolerance {_amount(tolerance)} times" if tolerance is not None else ""
        if bits:
            lines.append(
                f"Expected price ({price_currency}): {', '.join(bits)}{tolerance_text}.".rstrip()
            )

    fee_policy = intent.get("fee_policy") or {}
    if fee_policy:
        codes = fee_policy.get("allowed_codes") or []
        code_text = ", ".join(str(code) for code in codes) if codes else "none"
        undisclosed = "accepted" if fee_policy.get("allow_undisclosed") else "not accepted"
        lines.append(f"Accepted fees: {code_text}. Undisclosed fees are {undisclosed}.")

    if mandate.get("delegation_id"):
        lines.append(f"Delegation: {mandate['delegation_id']}.")
    if mandate.get("revocation_endpoint"):
        lines.append(f"Revocation status is published at {mandate['revocation_endpoint']}.")

    acknowledgements = mandate.get("required_acknowledgements") or []
    if acknowledgements:
        lines.append(
            "Required acknowledgements before the agreement is active: "
            + ", ".join(str(role) for role in acknowledgements)
            + "."
        )

    lines.append("The agent cannot change these limits. You can revoke this agreement.")
    return "\n".join(lines)


def _window_line(not_before: Any, expires_at: Any) -> str:
    if not_before and expires_at:
        return f"Valid from {not_before} until {expires_at}."
    if expires_at:
        return f"Expires: {expires_at}."
    if not_before:
        return f"Valid from {not_before}. No expiry is declared."
    return "No time window is declared."


def _amount(value: Any) -> str:
    return encode_decimal(money(value))


def _one_line(value: str) -> str:
    return " ".join(value.split())
