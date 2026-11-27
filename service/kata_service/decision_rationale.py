# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Explain a KATA decision without changing it.

GAB_DECISION_RATIONALE defaults off. When it is on, the verify response gains
a rationale object: the decision's existing reason codes, a confidence from
0 to 1, and references to evidence records already stored for that decision.

Confidence is a fixed function of those reason codes, the agent's existing
trust score, and the evidence result the Phase 0 verifier already recorded.
There is no model and no learned weight. A missing or unreadable evidence
row contributes nothing and does not fail the decision.
"""

from __future__ import annotations

import logging
from typing import Any

log = logging.getLogger("kata_service.decision_rationale")

_ALLOW_FLOOR = 550
_ALLOW_SPAN = 400
_COLD_SPAN = 200
_DENY_DEFAULT = 880
_STEP_DEFAULT = 550
_VALID_DELTA = 30
_INVALID_DELTA = -40
_UNVERIFIABLE_DELTA = -15

# Thousandths. A deny uses the highest known code. A step-up uses the lowest.
_DENY_MILLI = {
    "ACK_KEY_MISMATCH": 950,
    "ACK_SIGNATURE_INVALID": 960,
    "ACTION_EXCEEDS_INTENT": 920,
    "ACTION_MALFORMED": 860,
    "ACTION_NOT_ALLOWED": 920,
    "ACTION_REPLAY": 940,
    "ACTION_TIME_IN_FUTURE": 860,
    "AUTHORITY_CUMULATIVE_LIMIT": 930,
    "AUTHORITY_OBSERVE_ONLY": 960,
    "AUTHORITY_TX_LIMIT": 930,
    "AGENT_BINDING_MISMATCH": 960,
    "AGENT_AUTHORITY_UNAVAILABLE": 900,
    "AGENT_NOT_ACTIVE": 970,
    "AGENT_STOPPED": 970,
    "AGREEMENT_LOG_TAMPERED": 980,
    "AMOUNT_ABOVE_INTENT_CEILING": 930,
    "ASSERTED_INTENT_MISMATCH": 900,
    "CATEGORY_MISMATCH": 910,
    "CONSTRAINT_VIOLATED": 900,
    "COUNTERPARTY_NOT_ALLOWED": 910,
    "COUNTERPARTY_RISK_EXCEEDED": 900,
    "CUMULATIVE_LIMIT_EXCEEDED": 930,
    "CURRENCY_MISMATCH": 920,
    "DELEGATION_NOT_ACTIVE": 940,
    "DELEGATION_SCOPE_MISMATCH": 900,
    "FEE_NOT_ACCEPTED": 900,
    "FREQUENCY_LIMIT_EXCEEDED": 900,
    "LEDGER_MALFORMED": 860,
    "LEDGER_TAMPERED": 970,
    "LIMIT_INCONSISTENT": 910,
    "MANDATE_EXPIRED": 940,
    "MANDATE_NOT_ACTIVE": 950,
    "MANDATE_NOT_YET_VALID": 930,
    "MANDATE_REVOKED": 950,
    "MANDATE_SIGNATURE_INVALID": 980,
    "MANDATE_TAMPERED": 990,
    "MERCHANT_NOT_ALLOWED": 910,
    "NO_ACTIVE_AGREEMENT": 950,
    "PRINCIPAL_MISMATCH": 960,
    "RENDERING_MISMATCH": 930,
    "REVOCATION_LIST_UNAVAILABLE": 700,
    "REVOCATION_PUSH_INVALID": 900,
    "TRANSPARENCY_LOG_TAMPERED": 970,
    "TREE_HEAD_INVALID": 960,
    "UNDISCLOSED_FEE": 900,
    "VELOCITY_AMOUNT": 860,
    "VELOCITY_BURST": 780,
    "VELOCITY_CASHOUT": 760,
    "VELOCITY_COUNT": 860,
    "WINDOW_INCONSISTENT": 880,
}
_STEP_MILLI = {
    "AGENT_AUTHORITY_UNAVAILABLE": 560,
    "AGREEMENT_NOT_SELECTED": 580,
    "AUTHORITY_APPROVAL_REQUIRED": 560,
    "AUTHORITY_STEP_UP": 560,
    "AMOUNT_NOT_PROVIDED": 540,
    "COUNTERPARTY_ACK_REQUIRED": 560,
    "COUNTERPARTY_RISK_UNKNOWN": 520,
    "DEVICE_SIGNAL": 540,
    "FX_RATE_UNAVAILABLE": 500,
    "IP_SIGNAL": 540,
    "KEY_SIGNAL": 540,
    "NETWORK_SIGNAL": 540,
    "NETWORK_SIGNAL_STEP_UP": 560,
    "OVER_BROAD_INTENT": 620,
    "TIMING_SIGNAL": 540,
}


def reason_codes(payload: dict[str, Any]) -> list[str]:
    """Copy reason codes already on the decision. Other shapes are skipped."""

    raw = payload.get("reasons")
    if not isinstance(raw, list):
        return []
    codes: list[str] = []
    for item in raw:
        if isinstance(item, str) and item:
            codes.append(item)
        elif isinstance(item, dict):
            code = item.get("code")
            if isinstance(code, str) and code:
                codes.append(code)
    return codes


def confidence_milli(
    verdict: str,
    kata_decision: str,
    reasons: list[str],
    score: int,
    cold_start: bool,
    evidence_results: list[str],
) -> int:
    """Return confidence in thousandths, clamped to 0..1000."""

    stepped = kata_decision == "STEP_UP" or verdict == "STEP_UP"
    denied = (not stepped) and (verdict == "DENY" or kata_decision == "BLOCK")
    known = [value for value in (_code_milli(code, stepped) for code in reasons) if value is not None]
    if stepped:
        base = min(known) if known else _STEP_DEFAULT
    elif denied:
        base = max(known) if known else _DENY_DEFAULT
    elif known:
        base = min(known)
    else:
        base = _allow_milli(score, cold_start)
    total = base + _evidence_delta(evidence_results)
    if total < 0:
        return 0
    if total > 1000:
        return 1000
    return total


def confidence_for(
    verdict: str,
    kata_decision: str,
    reasons: list[str],
    score: int,
    cold_start: bool,
    evidence_results: list[str],
) -> float:
    """Return confidence in [0, 1]. The same inputs always return the same float."""

    return confidence_milli(verdict, kata_decision, reasons, score, cold_start, evidence_results) / 1000


def attach_rationale(bureau: Any, body: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
    """Add rationale when the flag is on. Otherwise return the same payload object."""

    if not getattr(bureau, "decision_rationale", False):
        return payload
    if not isinstance(payload, dict):
        return payload
    records = _records(bureau, body if isinstance(body, dict) else {}, payload)
    score, cold_start = _agent_signal(bureau, payload)
    codes = reason_codes(payload)
    results = _results(records)
    updated = dict(payload)
    updated["rationale"] = {
        "reasons": codes,
        "confidence": confidence_for(
            str(payload.get("verdict") or ""),
            str(payload.get("kata_decision") or ""),
            codes,
            score,
            cold_start,
            results,
        ),
        "evidence": [_reference(row) for row in records],
    }
    return updated


def _code_milli(code: str, stepped: bool) -> int | None:
    primary = _STEP_MILLI if stepped else _DENY_MILLI
    secondary = _DENY_MILLI if stepped else _STEP_MILLI
    if code in primary:
        return primary[code]
    if code in secondary:
        return secondary[code]
    return None


def _allow_milli(score: int, cold_start: bool) -> int:
    bounded = _bounded_score(score)
    milli = _ALLOW_FLOOR + bounded * _ALLOW_SPAN // 1000
    if cold_start:
        milli = min(milli, _ALLOW_FLOOR + bounded * _COLD_SPAN // 1000)
    return milli


def _bounded_score(score: int) -> int:
    if isinstance(score, bool) or not isinstance(score, int):
        try:
            score = int(score)
        except (TypeError, ValueError):
            return 0
    if score < 0:
        return 0
    if score > 1000:
        return 1000
    return score


def _evidence_delta(results: list[str]) -> int:
    if not results:
        return 0
    if any(item == "invalid" for item in results):
        return _INVALID_DELTA
    if all(item == "valid" for item in results):
        return _VALID_DELTA
    return _UNVERIFIABLE_DELTA


def _agent_signal(bureau: Any, payload: dict[str, Any]) -> tuple[int, bool]:
    agent_id = payload.get("agent_id")
    if not isinstance(agent_id, str) or not agent_id:
        return 0, True
    getter = getattr(getattr(bureau, "repo", None), "get_agent", None)
    if getter is None:
        return 0, True
    try:
        agent = getter(agent_id)
    except Exception:
        log.exception("agent score was not read for the decision rationale")
        return 0, True
    if not isinstance(agent, dict):
        return 0, True
    return _bounded_score(agent.get("score") or 0), bool(agent.get("cold_start", True))


def _records(bureau: Any, body: dict[str, Any], payload: dict[str, Any]) -> list[dict[str, Any]]:
    if not getattr(bureau, "evidence_verifier", False):
        return []
    store = getattr(bureau, "_evidence_store", None)
    if store is None:
        return []
    try:
        from kata_service.evidence.attach import decision_ref

        ref = decision_ref(body, payload)
        listed = store.list_evidence(ref)
    except Exception:
        log.exception("evidence records were not read for the decision rationale")
        return []
    if not isinstance(listed, list):
        return []
    rows: list[dict[str, Any]] = []
    for item in listed:
        if not isinstance(item, dict):
            continue
        if item.get("decision_ref") != ref:
            continue
        evidence_id = item.get("evidence_id")
        if not isinstance(evidence_id, str) or not evidence_id:
            continue
        rows.append(item)
    return rows


def _results(records: list[dict[str, Any]]) -> list[str]:
    results: list[str] = []
    for item in records:
        evidence = item.get("evidence")
        if not isinstance(evidence, dict):
            continue
        result = evidence.get("result")
        if isinstance(result, str) and result:
            results.append(result)
    return results


def _reference(row: dict[str, Any]) -> dict[str, Any]:
    evidence = row.get("evidence") if isinstance(row.get("evidence"), dict) else {}
    ref = {
        "evidence_id": row.get("evidence_id"),
        "decision_ref": row.get("decision_ref"),
    }
    digest = evidence.get("payload_hash")
    if isinstance(digest, str) and digest:
        ref["payload_hash"] = digest
    return ref
