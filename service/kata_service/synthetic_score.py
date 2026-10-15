# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""A small synthetic before/after for the bureau score. Not real customers.

Run from the service directory:

    python3 -m kata_service.synthetic_score
"""

from __future__ import annotations

from kata_service.bureau import trust_score
from kata_service.defenses import ScoreContext, ScorePolicy, ring_edges

DISCLAIMER = "SIMULATED / synthetic test data, not real customers"
NOW = "2026-10-15T12:00:00Z"
OLD = "2024-01-01T00:00:00Z"


def _settled(report_id: str, reporter: str, evidence: str, agent_id: str = "agent-subject") -> dict:
    return {
        "report_id": report_id,
        "agent_id": agent_id,
        "kind": "transaction_outcome",
        "evidence_hash": evidence,
        "reporter_org_id": reporter,
        "outcome": "settled",
        "excluded": False,
    }


def synthetic_case() -> dict:
    """Fabricated settled reports and one fake chargeback, scored both ways."""

    settled = [
        _settled(f"s{index}", "org-attacker", "sha256:" + f"{index:02x}" * 32)
        for index in range(1, 9)
    ]
    chargeback = {
        "report_id": "c1",
        "agent_id": "agent-legit",
        "kind": "chargeback",
        "evidence_hash": "sha256:" + "ab" * 32,
        "reporter_org_id": "org-attacker",
        "outcome": None,
        "excluded": False,
    }
    types = {"org-attacker": "merchant", "org-operator": "agent_operator", "org-partner": "agent_operator"}
    legacy = ScorePolicy.legacy()
    defended = ScorePolicy()
    unlinked = ScoreContext(now=NOW, reporter_created_at={"org-attacker": OLD}, linked_reporters=set())
    linked = ScoreContext(
        now=NOW,
        reporter_created_at={"org-attacker": OLD, "org-partner": OLD},
        linked_reporters={"org-attacker", "org-partner"},
    )
    reciprocal = [
        _settled("p1", "org-partner", "sha256:" + "11" * 32, "agent-subject"),
        _settled("p2", "org-operator", "sha256:" + "22" * 32, "agent-other"),
    ]
    subject_reports = [item for item in reciprocal if item["agent_id"] == "agent-subject"]
    edges = ring_edges({("org-partner", "org-operator"), ("org-operator", "org-partner")})
    ring_context = ScoreContext(
        now=NOW,
        reporter_created_at={"org-partner": OLD, "org-operator": OLD},
        linked_reporters={"org-partner"},
        ring_edges=edges,
    )
    legacy_settled = trust_score(
        verification_level="operator_verified",
        operator_status="active",
        operator_org_id="org-operator",
        reports=settled,
        disputes=[],
        reporter_types=types,
        policy=legacy,
    )
    defended_unlinked = trust_score(
        verification_level="operator_verified",
        operator_status="active",
        operator_org_id="org-operator",
        reports=settled,
        disputes=[],
        reporter_types=types,
        policy=defended,
        context=unlinked,
    )
    legacy_chargeback = trust_score(
        verification_level="operator_verified",
        operator_status="active",
        operator_org_id="org-operator",
        reports=[chargeback],
        disputes=[],
        reporter_types=types,
        policy=legacy,
    )
    defended_chargeback = trust_score(
        verification_level="operator_verified",
        operator_status="active",
        operator_org_id="org-operator",
        reports=[chargeback],
        disputes=[],
        reporter_types=types,
        policy=defended,
        context=unlinked,
    )
    legacy_ring = trust_score(
        verification_level="operator_verified",
        operator_status="active",
        operator_org_id="org-operator",
        reports=subject_reports,
        disputes=[],
        reporter_types=types,
        policy=legacy,
    )
    defended_ring = trust_score(
        verification_level="operator_verified",
        operator_status="active",
        operator_org_id="org-operator",
        reports=subject_reports,
        disputes=[],
        reporter_types=types,
        policy=defended,
        context=ring_context,
    )
    return {
        "label": "SIMULATED",
        "disclaimer": DISCLAIMER,
        "seed": "synthetic-defenses-v1",
        "legacy_settled_score": legacy_settled["score"],
        "defended_unlinked_score": defended_unlinked["score"],
        "legacy_chargeback_score": legacy_chargeback["score"],
        "defended_chargeback_score": defended_chargeback["score"],
        "legacy_ring_score": legacy_ring["score"],
        "defended_ring_score": defended_ring["score"],
        "ring_edges": sorted(edges),
    }


def main() -> None:
    result = synthetic_case()
    print(result["disclaimer"])
    print(
        "fabricated settled reports:"
        f" legacy {result['legacy_settled_score']},"
        f" defended without a recorded transaction {result['defended_unlinked_score']}"
    )
    print(
        "unlinked chargeback:"
        f" legacy {result['legacy_chargeback_score']},"
        f" defended {result['defended_chargeback_score']}"
    )
    print(
        "reciprocal settled report:"
        f" legacy {result['legacy_ring_score']},"
        f" defended {result['defended_ring_score']}"
    )


if __name__ == "__main__":
    main()
