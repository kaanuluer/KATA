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
    velocity_adaptive: bool = True
    velocity_daily_count: int = 25
    velocity_daily_amount: int = 15000
    velocity_high_score: int = 750
    velocity_high_multiplier: int = 3
    velocity_probation_multiplier: float = 0.5
    velocity_burst_multiple: float = 3
    velocity_burst_min_days: int = 3
    velocity_quiet_days: int = 7
    velocity_cashout_amount: int = 500
    velocity_score_rise_days: int = 7
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
    ring_min_cluster: int = 3
    ring_internal_ratio: float = 0.8
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


def cluster_edges(
    report_edges: set[tuple[str, str]],
    *,
    shared_groups: list[set[str]] | None = None,
    volumes: list[tuple[str, str, float]] | None = None,
    min_cluster: int = 3,
    internal_ratio: float = 0.8,
    search_limit: int = 20000,
) -> set[tuple[str, str]]:
    """Settled edges to drop.

    A strongly connected component catches a closed loop of any length.
    Organizations that share a signal are treated as one node, so a one-way
    reporter in that group does not get settled credit. A component of at
    least min_cluster organizations whose internal transaction volume is at
    least internal_ratio of its total volume is discounted the same way.
    """

    nodes: set[str] = set()
    for source, target in report_edges:
        if source and target:
            nodes.add(source)
            nodes.add(target)
    for group in shared_groups or []:
        nodes.update(item for item in group if item)
    for left, right, _amount in volumes or []:
        if left and right:
            nodes.add(left)
            nodes.add(right)
    parent = {node: node for node in nodes}

    def find(node: str) -> str:
        root = node
        while parent[root] != root:
            root = parent[root]
        while parent[node] != root:
            parent[node], node = root, parent[node]
        return root

    def union(left: str, right: str) -> None:
        if left not in parent or right not in parent:
            return
        root_left, root_right = find(left), find(right)
        if root_left != root_right:
            parent[root_right] = root_left

    for group in shared_groups or []:
        members = [item for item in group if item in parent]
        for item in members[1:]:
            union(members[0], item)

    directed: dict[str, set[str]] = {}
    for source, target in report_edges:
        if not source or not target or source == target:
            continue
        directed.setdefault(find(source), set()).add(find(target))
    for targets in list(directed.values()):
        for target in targets:
            directed.setdefault(target, set())
    component_of: dict[str, frozenset[str]] = {}
    for component in _strongly_connected(directed):
        if len(component) < 2:
            continue
        frozen = frozenset(component)
        for node in component:
            component_of[node] = frozen

    discounted: set[tuple[str, str]] = set()
    for source, target in report_edges:
        if not source or not target or source == target:
            continue
        left, right = find(source), find(target)
        if left == right or (left in component_of and component_of.get(left) == component_of.get(right)):
            discounted.add((source, target))

    if volumes:
        weight: dict[tuple[str, str], float] = {}
        for left, right, amount in volumes:
            if not left or not right or left == right or amount <= 0:
                continue
            key = (left, right) if left < right else (right, left)
            weight[key] = weight.get(key, 0.0) + float(amount)
        undirected: dict[str, set[str]] = {}
        for source, target in report_edges:
            if not source or not target or source == target:
                continue
            undirected.setdefault(source, set()).add(target)
            undirected.setdefault(target, set()).add(source)
        seen_reports: set[str] = set()
        for start in undirected:
            if start in seen_reports:
                continue
            stack = [start]
            component: set[str] = set()
            while stack:
                node = stack.pop()
                if node in seen_reports:
                    continue
                seen_reports.add(node)
                component.add(node)
                stack.extend(undirected.get(node, ()))
            if len(component) < min_cluster:
                continue
            internal = 0.0
            external = 0.0
            for (left, right), amount in weight.items():
                if left in component and right in component:
                    internal += amount
                elif (left in component) ^ (right in component):
                    external += amount
            total = internal + external
            if total <= 0 or internal / total < internal_ratio:
                continue
            for source, target in report_edges:
                if source in component and target in component:
                    discounted.add((source, target))
    if len(discounted) > search_limit:
        return set(list(discounted)[:search_limit])
    return discounted


def _strongly_connected(directed: dict[str, set[str]]) -> list[set[str]]:
    index = 0
    stack: list[str] = []
    on_stack: set[str] = set()
    indices: dict[str, int] = {}
    low: dict[str, int] = {}
    components: list[set[str]] = []

    def visit(node: str) -> None:
        nonlocal index
        indices[node] = index
        low[node] = index
        index += 1
        stack.append(node)
        on_stack.add(node)
        for nxt in directed.get(node, ()):
            if nxt not in indices:
                visit(nxt)
                low[node] = min(low[node], low[nxt])
            elif nxt in on_stack:
                low[node] = min(low[node], indices[nxt])
        if low[node] == indices[node]:
            component: set[str] = set()
            while stack:
                nxt = stack.pop()
                on_stack.discard(nxt)
                component.add(nxt)
                if nxt == node:
                    break
            components.append(component)

    for node in list(directed):
        if node not in indices:
            visit(node)
    return components


SEGMENT_WINDOWS = {
    "shopping": (8, 1000),
    "travel": (6, 2500),
    "treasury": (4, 5000),
    "assistant": (10, 800),
}


def velocity_reason(
    *,
    existing_count: int,
    existing_amount: Decimal,
    amount: Decimal | None,
    score: int,
    probation: bool,
    policy: ScorePolicy,
    segment: str | None = None,
    prior_daily_amounts: list[Decimal] | None = None,
    quiet_days: float | None = None,
    score_rose: bool = False,
) -> str | None:
    """Return a velocity reason when this allow should step up.

    The static daily caps still apply. A named segment uses the tighter of
    that cap and the segment window. A burst is today's amount against the
    agent's own earlier days. A cash-out is a large amount after a quiet
    stretch, or after settled credit landed recently.
    """

    if not policy.velocity:
        return None
    multiplier = float(policy.velocity_high_multiplier if score >= policy.velocity_high_score else 1)
    if probation:
        multiplier *= policy.velocity_probation_multiplier
    count_cap = policy.velocity_daily_count * multiplier
    amount_cap = Decimal(policy.velocity_daily_amount) * Decimal(str(multiplier))
    if policy.velocity_adaptive and segment in SEGMENT_WINDOWS:
        segment_count, segment_amount = SEGMENT_WINDOWS[segment]
        count_cap = min(count_cap, segment_count * multiplier)
        amount_cap = min(amount_cap, Decimal(segment_amount) * Decimal(str(multiplier)))
    if existing_count >= count_cap:
        return "VELOCITY_COUNT"
    if amount is not None and existing_amount + amount > amount_cap:
        return "VELOCITY_AMOUNT"
    if not policy.velocity_adaptive or amount is None:
        return None
    priors = [item for item in (prior_daily_amounts or []) if item > 0]
    median = _median(priors)
    today = existing_amount + amount
    if median is not None and len(priors) >= policy.velocity_burst_min_days and today > median * Decimal(str(policy.velocity_burst_multiple)):
        return "VELOCITY_BURST"
    if quiet_days is not None and quiet_days >= policy.velocity_quiet_days and amount >= Decimal(policy.velocity_cashout_amount):
        return "VELOCITY_CASHOUT"
    if score_rose and amount >= Decimal(policy.velocity_cashout_amount):
        if median is None or today > median * Decimal(str(policy.velocity_burst_multiple)):
            return "VELOCITY_CASHOUT"
    return None


def _median(values: list[Decimal]) -> Decimal | None:
    if not values:
        return None
    ordered = sorted(values)
    return ordered[len(ordered) // 2]


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
