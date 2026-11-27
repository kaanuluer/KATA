# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Per-agent authority that can only tighten a KATA decision.

GAB_AGENT_AUTHORITY defaults off. Callers pass the decision the current rules
already produced. An unassigned level and level 3 return that same object.
Levels 0, 1, and 2 may deny or step up. They do not turn a deny into a step-up
or an allow, and they do not turn a step-up into an allow.

This module does not read a database and does not revoke credentials.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from kata_intent.errors import KataError
from kata_intent.values import money

OBSERVE = 0
STEP_UP_ONLY = 1
LIMITED = 2
STANDARD = 3
LEVELS = (OBSERVE, STEP_UP_ONLY, LIMITED, STANDARD)

# Fixed level-2 ceilings. Effective ceilings are clamped to the agent's own
# intent maximum and agreement cumulative total before they are used.
LIMITED_APPROVAL = 25
LIMITED_PER_TRANSACTION = 100
LIMITED_CUMULATIVE = 100

REASON_STOPPED = "AGENT_STOPPED"
REASON_OBSERVE = "AUTHORITY_OBSERVE_ONLY"
REASON_STEP_UP = "AUTHORITY_STEP_UP"
REASON_TX = "AUTHORITY_TX_LIMIT"
REASON_CUMULATIVE = "AUTHORITY_CUMULATIVE_LIMIT"
REASON_APPROVAL = "AUTHORITY_APPROVAL_REQUIRED"
REASON_UNAVAILABLE = "AGENT_AUTHORITY_UNAVAILABLE"
_UNAVAILABLE = "Agent authority could not be applied."

# Deny is tighter than step-up, and step-up is tighter than allow.
VERDICT_RANK = {"ALLOW": 0, "STEP_UP": 1, "DENY": 2}


@dataclass(frozen=True, slots=True)
class AuthorityLimits:
    per_transaction: int | None
    cumulative: int | None
    approval: int | None


def tighter_or_equal(candidate: str, baseline: str) -> bool:
    """True when candidate is the same tightness as baseline, or tighter."""

    return VERDICT_RANK[candidate] >= VERDICT_RANK[baseline]


def effective_limits(
    level: int,
    intent_maximum: int | None,
    agreement_cumulative: int | None,
) -> AuthorityLimits:
    """Return the ceilings this level may use.

    The numbers are never higher than the agent's own intent maximum or
    agreement cumulative total. Level 3 reports those limits unchanged.
    """

    if level == STANDARD:
        return AuthorityLimits(intent_maximum, agreement_cumulative, None)
    if level == LIMITED:
        per_tx = LIMITED_PER_TRANSACTION
        cumulative = LIMITED_CUMULATIVE
        approval = LIMITED_APPROVAL
        if intent_maximum is not None:
            per_tx = min(per_tx, intent_maximum)
        if agreement_cumulative is not None:
            cumulative = min(cumulative, agreement_cumulative)
        approval = min(approval, per_tx)
        if agreement_cumulative is not None:
            approval = min(approval, agreement_cumulative)
        return AuthorityLimits(per_tx, cumulative, approval)
    per_tx = 0
    cumulative = 0
    if intent_maximum is not None:
        per_tx = min(per_tx, intent_maximum)
    if agreement_cumulative is not None:
        cumulative = min(cumulative, agreement_cumulative)
    return AuthorityLimits(per_tx, cumulative, None)


def read_authority_level(agent: Any) -> int | None:
    """Return the assigned level, or None when this agent has none.

    A missing ``authority_level`` key is unassigned. That is also the shape of
    an agent loaded from Postgres when ``022_agent_authority.sql`` has not been
    applied: the row has no authority columns, and the loader does not add the
    key. None is not an error and the caller keeps today's decision.

    A value that is present but not 0, 1, 2, or 3 raises. So does any error
    while reading the key. The caller treats that as an unknown level.
    """

    if "authority_level" not in agent:
        return None
    level = agent["authority_level"]
    if level is None:
        return None
    if isinstance(level, bool) or not isinstance(level, int) or level not in LEVELS:
        raise ValueError("authority level is not 0, 1, 2, or 3")
    return level


def authority_unavailable(payload: dict[str, Any], *, level: int | None, read_failed: bool = False) -> dict[str, Any]:
    """Fail closed when authority cannot be read or applied.

    A failed read does not know the level, so the decision is step-up.
    Level 0 becomes deny. Levels 1 and 2 become step-up, and an existing deny
    stays a deny. The reason code is ``AGENT_AUTHORITY_UNAVAILABLE``.
    """

    if not isinstance(payload, dict):
        payload = {}
    if read_failed:
        return _rewrite(payload, "STEP_UP", "STEP_UP", REASON_UNAVAILABLE, _UNAVAILABLE)
    if level == OBSERVE:
        return _rewrite(payload, "DENY", "BLOCK", REASON_UNAVAILABLE, _UNAVAILABLE)
    if level in (STEP_UP_ONLY, LIMITED):
        if payload.get("verdict") == "DENY":
            updated = dict(payload)
            reasons = [code for code in list(updated.get("reasons") or []) if code != REASON_UNAVAILABLE]
            updated["verdict"] = "DENY"
            updated["kata_decision"] = "BLOCK"
            updated["reasons"] = [REASON_UNAVAILABLE, *reasons]
            messages = [text for text in list(updated.get("messages") or []) if text != _UNAVAILABLE]
            updated["messages"] = [_UNAVAILABLE, *messages]
            updated["required_action"] = "NONE"
            return updated
        return _rewrite(payload, "STEP_UP", "STEP_UP", REASON_UNAVAILABLE, _UNAVAILABLE)
    return payload


def apply_authority(
    payload: dict[str, Any],
    *,
    stopped: bool,
    level: int | None,
    amount: int | None,
    spent: int,
    intent_maximum: int | None,
    agreement_cumulative: int | None,
) -> dict[str, Any]:
    """Tighten payload. Return the same object when the decision does not change."""

    if not isinstance(payload, dict):
        return payload
    if stopped:
        if payload.get("verdict") == "DENY" and payload.get("reasons") == [REASON_STOPPED]:
            return payload
        return _rewrite(payload, "DENY", "BLOCK", REASON_STOPPED, "This agent is stopped.")
    if level is None or level == STANDARD:
        return payload
    verdict = payload.get("verdict")
    if level == OBSERVE:
        if verdict == "DENY":
            return payload
        return _rewrite(payload, "DENY", "BLOCK", REASON_OBSERVE, "This agent is observe-only.")
    if level == STEP_UP_ONLY:
        if verdict != "ALLOW":
            return payload
        return _rewrite(
            payload,
            "STEP_UP",
            "STEP_UP",
            REASON_STEP_UP,
            "This agent requires step-up for every payment.",
        )
    if level != LIMITED or verdict != "ALLOW":
        return payload
    limits = effective_limits(LIMITED, intent_maximum, agreement_cumulative)
    charge = _whole(amount)
    if charge is None:
        return _rewrite(
            payload,
            "STEP_UP",
            "STEP_UP",
            REASON_APPROVAL,
            "The amount is above this agent's approval threshold.",
        )
    per_tx = limits.per_transaction if limits.per_transaction is not None else LIMITED_PER_TRANSACTION
    cumulative = limits.cumulative if limits.cumulative is not None else LIMITED_CUMULATIVE
    if charge > per_tx:
        return _rewrite(payload, "DENY", "BLOCK", REASON_TX, "The amount is above this agent's authority ceiling.")
    if spent + charge > cumulative:
        return _rewrite(
            payload,
            "DENY",
            "BLOCK",
            REASON_CUMULATIVE,
            "The amount is above this agent's authority cumulative limit.",
        )
    approval = limits.approval if limits.approval is not None else LIMITED_APPROVAL
    if charge > approval:
        return _rewrite(
            payload,
            "STEP_UP",
            "STEP_UP",
            REASON_APPROVAL,
            "The amount is above this agent's approval threshold.",
        )
    return payload


def agreement_bounds(document: dict[str, Any] | None, currency: str | None) -> tuple[int | None, int | None, int]:
    """Read the tightest signed ceilings and the currency already spent.

    A missing or unreadable field is omitted. This does not raise.
    """

    if not isinstance(document, dict):
        return None, None, 0
    maxima: list[int] = []
    cumulatives: list[int] = []
    mandates = document.get("mandates")
    if isinstance(mandates, list):
        for mandate in mandates:
            if not isinstance(mandate, dict):
                continue
            _collect(mandate.get("intent"), "maximum_amount", maxima)
            _collect(mandate.get("limits"), "cumulative_maximum", cumulatives)
            _collect(mandate.get("parent_limits"), "maximum_amount", maxima)
            _collect(mandate.get("parent_limits"), "cumulative_maximum", cumulatives)
    _collect(document.get("parent_limits"), "maximum_amount", maxima)
    _collect(document.get("parent_limits"), "cumulative_maximum", cumulatives)
    intent_maximum = min(maxima) if maxima else None
    agreement_cumulative = min(cumulatives) if cumulatives else None
    return intent_maximum, agreement_cumulative, _spent(document.get("spend_summary"), currency)


def _collect(container: Any, key: str, dest: list[int]) -> None:
    if not isinstance(container, dict):
        return
    number = _whole(container.get(key))
    if number is not None:
        dest.append(number)


def _spent(summary: Any, currency: str | None) -> int:
    if not isinstance(summary, dict) or not currency:
        return 0
    bucket = summary.get(currency)
    if not isinstance(bucket, dict):
        return 0
    total = 0
    for value in bucket.values():
        number = _whole(value)
        if number is not None and number > 0:
            total += number
    return total


def _whole(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        number = money(value)
    except (KataError, TypeError, ValueError):
        return None
    if number < 0:
        return None
    return int(number)


def _rewrite(payload: dict[str, Any], verdict: str, kata_decision: str, reason: str, message: str) -> dict[str, Any]:
    updated = dict(payload)
    updated["verdict"] = verdict
    updated["kata_decision"] = kata_decision
    updated["reasons"] = [reason]
    updated["messages"] = [message]
    updated["required_action"] = "HUMAN_APPROVAL" if verdict == "STEP_UP" else "NONE"
    return updated
