# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Replay a candidate decision rule on synthetic verify requests.

GAB_RULE_SANDBOX defaults off. The HTTP route is registered only when the flag
is on. This module does not open a database, read a ledger, or write evidence.
The inputs are a fixed-seed generator or a caller-supplied synthetic batch.
The live rule object is restored before the call returns.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import re
import sys
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Iterator, Mapping

from kata_service.agent_authority import apply_authority
from kata_service.decision_rationale import confidence_for
from kata_service.defenses import ScorePolicy

ROUTE = "/internal/rule-sandbox"
DEFAULT_SEED = 20261127
DEFAULT_COUNT = 24
MAX_BATCH = 100
SAMPLE_LIMIT = 8
_INTENT_CEILING = 1500
_INTENT_CUMULATIVE = 2000
_INTENT_CURRENCY = "CAD"
_ALLOWED_ACTIONS = ("purchase",)

_REQUEST_ID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_ACTION = re.compile(r"^[a-z0-9_-]{1,64}$")
_CURRENCY = re.compile(r"^[A-Z]{3}$")
_STATUSES = frozenset({"active", "suspended", "revoked"})
_EVIDENCE = frozenset({"valid", "invalid", "unverifiable"})
_BODY_KEYS = frozenset({"rules", "seed", "count", "requests"})
_RULE_FIELDS = {
    "maximum_amount": "maximum_amount",
    "ceiling": "maximum_amount",
    "cumulative_maximum": "cumulative_maximum",
    "currency": "currency",
    "allowed_actions": "allowed_actions",
    "velocity_daily_count": "velocity_daily_count",
    "velocity_daily_amount": "velocity_daily_amount",
    "velocity_enabled": "velocity_enabled",
}
_REQUEST_FIELDS = frozenset(
    {
        "request_id",
        "agent_status",
        "agreement_count",
        "amount",
        "currency",
        "action_type",
        "score",
        "cold_start",
        "prior_daily_count",
        "prior_daily_amount",
        "evidence_result",
        "authority_level",
        "authority_stopped",
        "intent_maximum",
        "agreement_cumulative",
        "spent",
    }
)
_AMOUNT_CHOICES = (0, 10, 50, 100, 250, 800, 1500, 1501, 5000)
_CURRENCY_CHOICES = ("CAD", "USD")
_STATUS_CHOICES = ("active", "active", "active", "suspended")
_AGREEMENT_CHOICES = (0, 1, 1, 1, 2)
_ACTION_CHOICES = ("purchase", "purchase", "transfer")
_SCORE_CHOICES = (0, 400, 620, 750, 1000)
_EVIDENCE_CHOICES = (None, None, "valid", "invalid", "unverifiable")
_PRIOR_COUNTS = (0, 0, 1, 24, 25)
_PRIOR_AMOUNTS = (0, 0, 100, 14999, 15000)


class SandboxError(Exception):
    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class DecisionRules:
    """Operator decision rules used only inside the sandbox."""

    maximum_amount: int
    cumulative_maximum: int
    currency: str
    allowed_actions: tuple[str, ...]
    velocity_daily_count: int
    velocity_daily_amount: int
    velocity_enabled: bool


@dataclass(frozen=True, slots=True)
class SyntheticRequest:
    request_id: str
    agent_status: str
    agreement_count: int
    amount: int
    currency: str
    action_type: str
    score: int | None
    cold_start: bool
    prior_daily_count: int
    prior_daily_amount: int
    evidence_result: str | None
    authority_level: int | None = None
    authority_stopped: bool = False
    intent_maximum: int | None = None
    agreement_cumulative: int | None = None
    spent: int = 0


def _baseline() -> DecisionRules:
    """Current sandbox rules. Velocity matches ScorePolicy defaults.

    The ceilings are the public sample intent: 1500 per charge and 2000
    cumulative. Nothing here is loaded from a database.
    """

    policy = ScorePolicy()
    return DecisionRules(
        maximum_amount=_INTENT_CEILING,
        cumulative_maximum=_INTENT_CUMULATIVE,
        currency=_INTENT_CURRENCY,
        allowed_actions=_ALLOWED_ACTIONS,
        velocity_daily_count=policy.velocity_daily_count,
        velocity_daily_amount=policy.velocity_daily_amount,
        velocity_enabled=policy.velocity,
    )


LIVE_RULES = _baseline()


def live_rules() -> DecisionRules:
    """Return the process live rule object. Callers must not replace it."""

    return LIVE_RULES


def _capture(rules: DecisionRules) -> DecisionRules:
    return DecisionRules(
        maximum_amount=rules.maximum_amount,
        cumulative_maximum=rules.cumulative_maximum,
        currency=rules.currency,
        allowed_actions=rules.allowed_actions,
        velocity_daily_count=rules.velocity_daily_count,
        velocity_daily_amount=rules.velocity_daily_amount,
        velocity_enabled=rules.velocity_enabled,
    )


def _restore(rules: DecisionRules, saved: DecisionRules) -> None:
    object.__setattr__(rules, "maximum_amount", saved.maximum_amount)
    object.__setattr__(rules, "cumulative_maximum", saved.cumulative_maximum)
    object.__setattr__(rules, "currency", saved.currency)
    object.__setattr__(rules, "allowed_actions", saved.allowed_actions)
    object.__setattr__(rules, "velocity_daily_count", saved.velocity_daily_count)
    object.__setattr__(rules, "velocity_daily_amount", saved.velocity_daily_amount)
    object.__setattr__(rules, "velocity_enabled", saved.velocity_enabled)


@contextmanager
def _guard_live() -> Iterator[DecisionRules]:
    """Copy the live rules, then put the same object back on the way out."""

    global LIVE_RULES
    live = LIVE_RULES
    saved = _capture(live)
    try:
        yield saved
    finally:
        _restore(live, saved)
        if LIVE_RULES is not live:
            LIVE_RULES = live


def run_sandbox(body: Any) -> dict[str, Any]:
    """Compare candidate rules with the live rules. Synthetic input only."""

    with _guard_live() as current:
        if not isinstance(body, dict):
            raise SandboxError("sandbox body must be a JSON object")
        unknown = [key for key in body if key not in _BODY_KEYS]
        if unknown:
            raise SandboxError("unknown sandbox field " + unknown[0])
        candidate = _candidate(current, body.get("rules", {}))
        requests, source, seed = _batch(body)
        return _report(current, candidate, requests, source, seed)


def generate_requests(seed: int, count: int) -> tuple[SyntheticRequest, ...]:
    """Build a synthetic batch. The same seed and count always return the same rows."""

    if isinstance(seed, bool) or not isinstance(seed, int) or seed < 0 or seed > 2_147_483_647:
        raise SandboxError("seed must be an integer from 0 to 2147483647")
    if isinstance(count, bool) or not isinstance(count, int) or count < 1 or count > MAX_BATCH:
        raise SandboxError(f"batch is limited to {MAX_BATCH} requests")
    rng = random.Random(seed)
    rows: list[SyntheticRequest] = []
    for index in range(count):
        evidence = rng.choice(_EVIDENCE_CHOICES)
        raw = {
            "request_id": f"syn-{index:04d}",
            "agent_status": rng.choice(_STATUS_CHOICES),
            "agreement_count": rng.choice(_AGREEMENT_CHOICES),
            "amount": rng.choice(_AMOUNT_CHOICES),
            "currency": rng.choice(_CURRENCY_CHOICES),
            "action_type": rng.choice(_ACTION_CHOICES),
            "score": rng.choice(_SCORE_CHOICES),
            "cold_start": rng.choice((True, False)),
            "prior_daily_count": rng.choice(_PRIOR_COUNTS),
            "prior_daily_amount": rng.choice(_PRIOR_AMOUNTS),
        }
        if evidence is not None:
            raw["evidence_result"] = evidence
        rows.append(_parse_request(raw, index))
    return tuple(rows)


def _batch(body: Mapping[str, Any]) -> tuple[tuple[SyntheticRequest, ...], str, int | None]:
    supplied = body.get("requests", None)
    if supplied is not None:
        if "seed" in body:
            raise SandboxError("seed is only used for a generated batch")
        if not isinstance(supplied, list):
            raise SandboxError("requests must be an array")
        if not supplied:
            raise SandboxError("batch is empty")
        if len(supplied) > MAX_BATCH:
            raise SandboxError(f"batch is limited to {MAX_BATCH} requests")
        if "count" in body and body.get("count") != len(supplied):
            raise SandboxError("count does not match the batch")
        parsed = tuple(_parse_request(item, index) for index, item in enumerate(supplied))
        _unique(parsed)
        return parsed, "batch", None
    seed = body.get("seed", DEFAULT_SEED)
    count = body.get("count", DEFAULT_COUNT)
    rows = generate_requests(seed, count)
    return rows, "generated", seed


def _unique(rows: tuple[SyntheticRequest, ...]) -> None:
    seen: set[str] = set()
    for row in rows:
        if row.request_id in seen:
            raise SandboxError("duplicate request_id " + row.request_id)
        seen.add(row.request_id)


def _candidate(current: DecisionRules, rules: Any) -> DecisionRules:
    if rules is None:
        rules = {}
    if not isinstance(rules, dict):
        raise SandboxError("candidate rules must be an object")
    found: dict[str, Any] = {}
    for key, value in rules.items():
        field = _RULE_FIELDS.get(key)
        if field is None:
            raise SandboxError("unknown candidate rule " + str(key))
        if field in found:
            raise SandboxError("overlapping rules for " + field)
        found[field] = value
    amount = _optional_int(found, "maximum_amount", current.maximum_amount, 0, 1_000_000_000)
    cumulative = _optional_int(found, "cumulative_maximum", current.cumulative_maximum, 0, 1_000_000_000_000)
    currency = _optional_currency(found, current.currency)
    actions = _optional_actions(found, current.allowed_actions)
    count = _optional_int(found, "velocity_daily_count", current.velocity_daily_count, 1, 1_000_000)
    daily = _optional_int(found, "velocity_daily_amount", current.velocity_daily_amount, 0, 1_000_000_000_000)
    enabled = _optional_bool(found, "velocity_enabled", current.velocity_enabled)
    return DecisionRules(amount, cumulative, currency, actions, count, daily, enabled)


def _optional_int(found: Mapping[str, Any], name: str, default: int, low: int, high: int) -> int:
    if name not in found:
        return default
    return _strict_int(found[name], name, low, high)


def _strict_int(value: Any, name: str, low: int, high: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise SandboxError(name + " must be an integer")
    if value < low or value > high:
        raise SandboxError(name + " is out of range")
    return value


def _optional_currency(found: Mapping[str, Any], default: str) -> str:
    if "currency" not in found:
        return default
    value = found["currency"]
    if not isinstance(value, str) or _CURRENCY.fullmatch(value) is None:
        raise SandboxError("currency is three letters")
    return value


def _optional_actions(found: Mapping[str, Any], default: tuple[str, ...]) -> tuple[str, ...]:
    if "allowed_actions" not in found:
        return default
    value = found["allowed_actions"]
    if not isinstance(value, list):
        raise SandboxError("allowed_actions must be a list")
    if len(value) > 32:
        raise SandboxError("allowed_actions is too long")
    actions: list[str] = []
    for item in value:
        if not isinstance(item, str) or _ACTION.fullmatch(item) is None:
            raise SandboxError("allowed_actions entries are short action names")
        if item not in actions:
            actions.append(item)
    return tuple(actions)


def _optional_bool(found: Mapping[str, Any], name: str, default: bool) -> bool:
    if name not in found:
        return default
    value = found[name]
    if not isinstance(value, bool):
        raise SandboxError(name + " must be true or false")
    return value


def _parse_request(raw: Any, index: int) -> SyntheticRequest:
    label = f"synthetic request {index}"
    if not isinstance(raw, dict):
        raise SandboxError(label + " must be an object")
    unknown = [key for key in raw if key not in _REQUEST_FIELDS]
    if unknown:
        raise SandboxError("unknown synthetic request field " + str(unknown[0]))
    request_id = raw.get("request_id")
    if not isinstance(request_id, str) or _REQUEST_ID.fullmatch(request_id) is None:
        raise SandboxError(label + " request_id is invalid")
    status = raw.get("agent_status")
    if not isinstance(status, str) or status not in _STATUSES:
        raise SandboxError(label + " agent_status is invalid")
    agreements = _strict_int(raw.get("agreement_count"), label + " agreement_count", 0, 100)
    amount = _strict_int(raw.get("amount"), label + " amount", 0, 1_000_000_000_000)
    currency = raw.get("currency")
    if not isinstance(currency, str) or _CURRENCY.fullmatch(currency) is None:
        raise SandboxError(label + " currency is three letters")
    action = raw.get("action_type")
    if not isinstance(action, str) or _ACTION.fullmatch(action) is None:
        raise SandboxError(label + " action_type is invalid")
    score = None
    if "score" in raw and raw.get("score") is not None:
        score = _strict_int(raw.get("score"), label + " score", 0, 1000)
    cold = True
    if "cold_start" in raw:
        if not isinstance(raw.get("cold_start"), bool):
            raise SandboxError(label + " cold_start must be true or false")
        cold = raw["cold_start"]
    prior_count = 0
    if "prior_daily_count" in raw:
        prior_count = _strict_int(raw.get("prior_daily_count"), label + " prior_daily_count", 0, 1_000_000)
    prior_amount = 0
    if "prior_daily_amount" in raw:
        prior_amount = _strict_int(raw.get("prior_daily_amount"), label + " prior_daily_amount", 0, 1_000_000_000_000)
    evidence = None
    if "evidence_result" in raw and raw.get("evidence_result") is not None:
        evidence = raw.get("evidence_result")
        if not isinstance(evidence, str) or evidence not in _EVIDENCE:
            raise SandboxError(label + " evidence_result is invalid")
    authority_level = None
    if "authority_level" in raw and raw.get("authority_level") is not None:
        authority_level = _strict_int(raw.get("authority_level"), label + " authority_level", 0, 3)
    authority_stopped = False
    if "authority_stopped" in raw:
        if not isinstance(raw.get("authority_stopped"), bool):
            raise SandboxError(label + " authority_stopped must be true or false")
        authority_stopped = raw["authority_stopped"]
    intent_maximum = None
    if "intent_maximum" in raw and raw.get("intent_maximum") is not None:
        intent_maximum = _strict_int(raw.get("intent_maximum"), label + " intent_maximum", 0, 1_000_000_000_000)
    agreement_cumulative = None
    if "agreement_cumulative" in raw and raw.get("agreement_cumulative") is not None:
        agreement_cumulative = _strict_int(
            raw.get("agreement_cumulative"),
            label + " agreement_cumulative",
            0,
            1_000_000_000_000,
        )
    spent = 0
    if "spent" in raw:
        spent = _strict_int(raw.get("spent"), label + " spent", 0, 1_000_000_000_000)
    return SyntheticRequest(
        request_id=request_id,
        agent_status=status,
        agreement_count=agreements,
        amount=amount,
        currency=currency,
        action_type=action,
        score=score,
        cold_start=cold,
        prior_daily_count=prior_count,
        prior_daily_amount=prior_amount,
        evidence_result=evidence,
        authority_level=authority_level,
        authority_stopped=authority_stopped,
        intent_maximum=intent_maximum,
        agreement_cumulative=agreement_cumulative,
        spent=spent,
    )


def _decide(rules: DecisionRules, request: SyntheticRequest) -> dict[str, Any]:
    decided = _decide_current(rules, request)
    ceiling = rules.maximum_amount if request.intent_maximum is None else min(rules.maximum_amount, request.intent_maximum)
    cumulative = (
        rules.cumulative_maximum
        if request.agreement_cumulative is None
        else min(rules.cumulative_maximum, request.agreement_cumulative)
    )
    return apply_authority(
        decided,
        stopped=request.authority_stopped,
        level=request.authority_level,
        amount=request.amount,
        spent=request.spent,
        intent_maximum=ceiling,
        agreement_cumulative=cumulative,
    )


def _decide_current(rules: DecisionRules, request: SyntheticRequest) -> dict[str, Any]:
    if request.agent_status != "active":
        return _outcome("DENY", "BLOCK", ["AGENT_NOT_ACTIVE"])
    if request.agreement_count <= 0:
        return _outcome("DENY", "BLOCK", ["NO_ACTIVE_AGREEMENT"])
    if request.agreement_count > 1:
        return _outcome("STEP_UP", "STEP_UP", ["AGREEMENT_NOT_SELECTED"])
    reasons: list[str] = []
    ceiling = rules.maximum_amount
    if request.intent_maximum is not None:
        ceiling = min(ceiling, request.intent_maximum)
    cumulative = rules.cumulative_maximum
    if request.agreement_cumulative is not None:
        cumulative = min(cumulative, request.agreement_cumulative)
    if request.action_type not in rules.allowed_actions:
        reasons.append("ACTION_NOT_ALLOWED")
        reasons.append("ACTION_EXCEEDS_INTENT")
    if request.amount > ceiling:
        reasons.append("AMOUNT_ABOVE_INTENT_CEILING")
        if "ACTION_EXCEEDS_INTENT" not in reasons:
            reasons.append("ACTION_EXCEEDS_INTENT")
    if request.currency != rules.currency:
        reasons.append("CURRENCY_MISMATCH")
    elif request.spent + request.amount > cumulative:
        reasons.append("CUMULATIVE_LIMIT_EXCEEDED")
    if reasons:
        return _outcome("DENY", "BLOCK", reasons)
    if rules.velocity_enabled:
        if request.prior_daily_count >= rules.velocity_daily_count:
            return _outcome("DENY", "BLOCK", ["VELOCITY_COUNT"])
        if request.prior_daily_amount + request.amount > rules.velocity_daily_amount:
            return _outcome("DENY", "BLOCK", ["VELOCITY_AMOUNT"])
    return _outcome("ALLOW", "ALLOW", [])


def _outcome(verdict: str, kata_decision: str, reasons: list[str]) -> dict[str, Any]:
    return {"verdict": verdict, "kata_decision": kata_decision, "reasons": list(reasons)}


def _rationale(decision: Mapping[str, Any], request: SyntheticRequest) -> dict[str, Any]:
    reasons = list(decision["reasons"])
    rationale: dict[str, Any] = {"reasons": reasons}
    if request.score is None:
        return rationale
    evidence = [] if request.evidence_result is None else [request.evidence_result]
    rationale["confidence"] = confidence_for(
        str(decision["verdict"]),
        str(decision["kata_decision"]),
        reasons,
        request.score,
        request.cold_start,
        evidence,
    )
    return rationale


def _record(request: SyntheticRequest, current: Mapping[str, Any], candidate: Mapping[str, Any]) -> dict[str, Any]:
    flipped = current["verdict"] != candidate["verdict"] or current["reasons"] != candidate["reasons"]
    return {
        "request_id": request.request_id,
        "flipped": flipped,
        "current": {"verdict": current["verdict"], "kata_decision": current["kata_decision"], "reasons": list(current["reasons"])},
        "candidate": {
            "verdict": candidate["verdict"],
            "kata_decision": candidate["kata_decision"],
            "reasons": list(candidate["reasons"]),
        },
        "rationale": {"current": _rationale(current, request), "candidate": _rationale(candidate, request)},
    }


def _counts(verdicts: list[str]) -> dict[str, int]:
    return {
        "allow": verdicts.count("ALLOW"),
        "deny": verdicts.count("DENY"),
        "step_up": verdicts.count("STEP_UP"),
    }


def _rules_dict(rules: DecisionRules) -> dict[str, Any]:
    return {
        "allowed_actions": list(rules.allowed_actions),
        "cumulative_maximum": rules.cumulative_maximum,
        "currency": rules.currency,
        "maximum_amount": rules.maximum_amount,
        "velocity_daily_amount": rules.velocity_daily_amount,
        "velocity_daily_count": rules.velocity_daily_count,
        "velocity_enabled": rules.velocity_enabled,
    }


def _summary(batch_size: int, source: str, seed: int | None, counts: Mapping[str, Mapping[str, int]], flips: int) -> str:
    current = counts["current"]
    candidate = counts["candidate"]
    changed = counts["changed"]
    seed_text = "none" if seed is None else str(seed)
    return (
        f"{batch_size} synthetic requests from {source} seed {seed_text}. "
        f"current allow {current['allow']} deny {current['deny']} step_up {current['step_up']}. "
        f"candidate allow {candidate['allow']} deny {candidate['deny']} step_up {candidate['step_up']}. "
        f"changed allow {changed['allow']} deny {changed['deny']} step_up {changed['step_up']}. "
        f"flips {flips}."
    )


def _report(
    current: DecisionRules,
    candidate: DecisionRules,
    requests: tuple[SyntheticRequest, ...],
    source: str,
    seed: int | None,
) -> dict[str, Any]:
    rows = []
    current_verdicts: list[str] = []
    candidate_verdicts: list[str] = []
    for request in requests:
        now = _decide(current, request)
        proposed = _decide(candidate, request)
        current_verdicts.append(now["verdict"])
        candidate_verdicts.append(proposed["verdict"])
        rows.append(_record(request, now, proposed))
    current_counts = _counts(current_verdicts)
    candidate_counts = _counts(candidate_verdicts)
    changed = {
        "allow": candidate_counts["allow"] - current_counts["allow"],
        "deny": candidate_counts["deny"] - current_counts["deny"],
        "step_up": candidate_counts["step_up"] - current_counts["step_up"],
    }
    counts = {"current": current_counts, "candidate": candidate_counts, "changed": changed}
    flips = sorted((row for row in rows if row["flipped"]), key=lambda row: row["request_id"])
    report = {
        "summary": _summary(len(requests), source, seed, counts, len(flips)),
        "source": source,
        "seed": seed,
        "batch_size": len(requests),
        "rules": {"current": _rules_dict(current), "candidate": _rules_dict(candidate)},
        "counts": counts,
        "changed": changed,
        "flips": flips,
        "samples": rows[:SAMPLE_LIMIT],
    }
    report["digest"] = _digest(report)
    return report


def _digest(report: Mapping[str, Any]) -> str:
    body = {key: value for key, value in report.items() if key != "digest"}
    raw = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def main(argv: list[str] | None = None) -> int:
    """Replay from the command line. This does not read the process environment."""

    parser = argparse.ArgumentParser(description="Replay a candidate decision rule on synthetic verify requests.")
    parser.add_argument("--seed", type=int, default=None)
    parser.add_argument("--count", type=int, default=None)
    parser.add_argument("--maximum-amount", type=int, default=None)
    parser.add_argument("--rules", default=None)
    parser.add_argument("--requests", default=None)
    parsed = parser.parse_args(argv)
    body: dict[str, Any] = {}
    try:
        rules: dict[str, Any] = {}
        if parsed.rules is not None:
            loaded = json.loads(parsed.rules)
            if not isinstance(loaded, dict):
                raise SandboxError("candidate rules must be an object")
            rules.update(loaded)
        if parsed.maximum_amount is not None:
            if "maximum_amount" in rules or "ceiling" in rules:
                raise SandboxError("overlapping rules for maximum_amount")
            rules["maximum_amount"] = parsed.maximum_amount
        if rules:
            body["rules"] = rules
        if parsed.requests is not None:
            loaded_requests = json.loads(parsed.requests)
            if not isinstance(loaded_requests, list):
                raise SandboxError("requests must be an array")
            body["requests"] = loaded_requests
        else:
            if parsed.seed is not None:
                body["seed"] = parsed.seed
            if parsed.count is not None:
                body["count"] = parsed.count
        report = run_sandbox(body)
    except SandboxError as exc:
        print(exc.message, file=sys.stderr)
        return 2
    except json.JSONDecodeError:
        print("rules and requests must be JSON", file=sys.stderr)
        return 2
    print(json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False))
    return 0
