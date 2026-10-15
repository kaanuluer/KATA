# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Configurable defenses around the bureau trust score.

The defaults are the product behavior. ScorePolicy.legacy() reproduces the
earlier formula, which trusted a report without checking that the reporter
had transacted with the agent.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal
from typing import Any

from kata_service.score_model import ScoreWeights


@dataclass(frozen=True)
class ScorePolicy:
    require_transaction_link: bool = True
    reporter_reputation: bool = True
    positive_cap: bool = True
    settled_cap_total: int = 25
    settled_cap_per_reporter: int = 16
    new_reporter_days: int = 30
    new_reporter_weight: float = 0.3
    ring_detection: bool = True
    velocity: bool = True
    velocity_daily_count: int = 25
    velocity_daily_amount: int = 15000
    velocity_high_score: int = 750
    velocity_high_multiplier: int = 3
    velocity_probation_multiplier: float = 0.5
    rereg_link: bool = True
    rereg_lookback_days: int = 14
    rereg_signal_lookback_days: int = 90
    rereg_malicious_lookback_days: int = 180
    rereg_penalty: int = 80
    rereg_penalty_cap: int = 200
    inherit_history: bool = True
    inherit_half_life_days: int = 30
    deny_score: int = 500
    dispute_hold: bool = True
    probation_days: int = 14
    require_proofing: bool = True
    weights: ScoreWeights = field(default_factory=ScoreWeights)
    ring_max_cycle: int = 4
    ring_search_limit: int = 20000

    @classmethod
    def legacy(cls) -> ScorePolicy:
        """The score as it behaved before these defenses."""

        return cls(
            require_transaction_link=False,
            reporter_reputation=False,
            positive_cap=False,
            ring_detection=False,
            velocity=False,
            rereg_link=False,
            inherit_history=False,
            dispute_hold=False,
        )


@dataclass
class ScoreContext:
    now: str = ""
    reporter_created_at: dict[str, str] = field(default_factory=dict)
    upheld_by_reporter: dict[str, int] = field(default_factory=dict)
    linked_reporters: set[str] | None = None
    linked_actions: dict[str, set[str]] = field(default_factory=dict)
    ring_edges: set[tuple[str, str]] = field(default_factory=set)
    open_dispute_ids: set[str] = field(default_factory=set)
    identity_penalty: int = 0
    inherited_reports: list[dict[str, Any]] = field(default_factory=list)


def effective_assurance(claimed: str, methods: set[str], *, require_proofing: bool) -> str:
    """Cap a claimed verification level at the proofs on file.

    key_binding supports key_bound. operator_review supports operator_verified.
    institution_attestation supports institution_attested. With the gate off,
    the claim is used as-is.
    """

    if not require_proofing:
        return claimed
    if claimed == "institution_attested" and "institution_attestation" in methods:
        return "institution_attested"
    if claimed in {"institution_attested", "operator_verified"} and "operator_review" in methods:
        return "operator_verified"
    if "key_binding" in methods or claimed == "key_bound":
        return "key_bound" if claimed != "unverified" else "unverified"
    if claimed == "unverified":
        return "unverified"
    return "unverified"


def reputation_multiplier(org_id: str, policy: ScorePolicy, context: ScoreContext) -> float:
    if not policy.reporter_reputation:
        return 1.0
    created = context.reporter_created_at.get(org_id)
    age = None if created is None or not context.now else age_days(created, context.now)
    multiplier = 1.0
    if age is None or age < policy.new_reporter_days:
        multiplier *= policy.new_reporter_weight
    upheld = context.upheld_by_reporter.get(org_id, 0)
    if upheld > 0:
        multiplier *= 0.5 ** min(upheld, 8)
    return multiplier


def report_is_linked(report: dict[str, Any], context: ScoreContext) -> bool:
    org_id = report.get("reporter_org_id") or ""
    linked = context.linked_reporters
    if linked is None or org_id not in linked:
        return False
    action_id = report.get("action_id")
    if not action_id:
        return True
    return action_id in context.linked_actions.get(org_id, set())


def reporter_is_young(org_id: str, policy: ScorePolicy, context: ScoreContext) -> bool:
    created = context.reporter_created_at.get(org_id)
    if not created or not context.now:
        return True
    age = age_days(created, context.now)
    return age is None or age < policy.new_reporter_days


def cap_settled_points(grants: list[tuple[int, str]], *, per_reporter: int, total: int) -> int:
    """Diminishing settled credit, then per-reporter and total caps.

    grants are (points, reporter_org_id). The first settled report from a
    reporter keeps its points. Each further report from that reporter is half
    of its own points, then a quarter, and so on.
    """

    ordered = sorted(grants, key=lambda item: item[0], reverse=True)
    used: dict[str, int] = {}
    seen: dict[str, int] = {}
    granted = 0
    for points, reporter in ordered:
        if points <= 0:
            continue
        generation = seen.get(reporter, 0)
        diminished = points if generation == 0 else int(round(points / (2**generation)))
        room_reporter = max(0, per_reporter - used.get(reporter, 0))
        room_total = max(0, total - granted)
        give = min(diminished, room_reporter, room_total)
        if give <= 0:
            seen[reporter] = generation + 1
            continue
        used[reporter] = used.get(reporter, 0) + give
        seen[reporter] = generation + 1
        granted += give
    return granted


def ring_edges(edges: set[tuple[str, str]], *, max_cycle: int = 4, search_limit: int = 20000) -> set[tuple[str, str]]:
    """Settled-report edges that sit on a cycle of length 2 through max_cycle.

    An edge is (reporter_org_id, subject_operator_org_id). A reciprocal pair
    is a 2-cycle. Longer closed loops stop at max_cycle. The search stops
    after search_limit steps and returns whatever it has found.
    """

    directed: dict[str, set[str]] = {}
    for source, target in edges:
        if source and target and source != target:
            directed.setdefault(source, set()).add(target)
    discounted: set[tuple[str, str]] = set()
    steps = 0
    for start in directed:
        stack: list[tuple[str, list[str]]] = [(start, [start])]
        while stack:
            node, path = stack.pop()
            steps += 1
            if steps > search_limit:
                return discounted
            for nxt in directed.get(node, ()):
                if nxt == start and 2 <= len(path) <= max_cycle:
                    seq = path + [start]
                    for index in range(len(path)):
                        discounted.add((seq[index], seq[index + 1]))
                elif nxt not in path and len(path) < max_cycle:
                    stack.append((nxt, path + [nxt]))
    return discounted


def velocity_reason(
    *,
    existing_count: int,
    existing_amount: Decimal,
    amount: Decimal | None,
    score: int,
    probation: bool,
    policy: ScorePolicy,
) -> str | None:
    """Return VELOCITY_COUNT or VELOCITY_AMOUNT when this allow should step up."""

    if not policy.velocity:
        return None
    multiplier = float(policy.velocity_high_multiplier if score >= policy.velocity_high_score else 1)
    if probation:
        multiplier *= policy.velocity_probation_multiplier
    count_cap = policy.velocity_daily_count * multiplier
    amount_cap = Decimal(policy.velocity_daily_amount) * Decimal(str(multiplier))
    if existing_count >= count_cap:
        return "VELOCITY_COUNT"
    if amount is not None and existing_amount + amount > amount_cap:
        return "VELOCITY_AMOUNT"
    return None


def window_totals(rows: list[dict[str, Any]], *, day: str, currency: str) -> tuple[int, Decimal]:
    count = 0
    total = Decimal(0)
    for row in rows:
        if not str(row.get("at") or "").startswith(day):
            continue
        count += 1
        if row.get("currency") == currency and row.get("amount") not in (None, ""):
            total += Decimal(str(row["amount"]))
    return count, total


def confirmed_malicious(agent: dict[str, Any], reports: list[dict[str, Any]] | None = None) -> bool:
    """Revoked, suspended, or a fraud report still on the agent."""

    if agent.get("status") in {"suspended", "revoked"}:
        return True
    for report in reports or []:
        if report.get("kind") == "fraud_incident" and not report.get("excluded"):
            return True
    return False


def lookback_days(agent: dict[str, Any], policy: ScorePolicy, reports: list[dict[str, Any]] | None = None, *, signal: bool) -> int:
    """How far back a denied agent can still be linked.

    A shared signal outlives the same-operator window. A confirmed-malicious
    agent uses the longest window, with or without a signal.
    """

    if confirmed_malicious(agent, reports):
        return policy.rereg_malicious_lookback_days
    if signal:
        return policy.rereg_signal_lookback_days
    return policy.rereg_lookback_days


def decay_factor(start: str, now: str, half_life_days: int) -> float:
    """1 at the link, half after one half-life, and so on."""

    if half_life_days <= 0:
        return 1.0
    age = age_days(start, now)
    if age is None or age <= 0:
        return 1.0
    return float(0.5 ** (age / half_life_days))


def agent_is_denied(agent: dict[str, Any], policy: ScorePolicy) -> bool:
    if agent.get("status") in {"suspended", "revoked"}:
        return True
    return int(agent.get("score") or 0) < policy.deny_score


def within_days(at: str, now: str, days: int) -> bool:
    age = age_days(at, now)
    return age is not None and 0 <= age <= days


def inheritance_penalty(agents: list[dict[str, Any]], *, now: str, policy: ScorePolicy) -> int:
    worst = 0
    for agent in agents:
        if not within_days(str(agent.get("updated_at") or ""), now, policy.rereg_lookback_days):
            continue
        if not agent_is_denied(agent, policy):
            continue
        deficit = max(0, policy.deny_score - int(agent.get("score") or 0))
        worst = max(worst, min(policy.rereg_penalty_cap, max(policy.rereg_penalty, deficit)))
    return worst


def age_days(start: str, end: str) -> float | None:
    try:
        opened = datetime.strptime(start[:19], "%Y-%m-%dT%H:%M:%S")
        closed = datetime.strptime(end[:19], "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        return None
    return (closed - opened).total_seconds() / 86400
