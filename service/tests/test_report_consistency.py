# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Coordinated or contradictory negative reports weigh less."""

from __future__ import annotations

from kata_service.bureau import trust_score
from kata_service.defenses import ScoreContext, ScorePolicy


def _chargeback(report_id: str, reporter: str, evidence: str, agent_id: str = "shopper-01") -> dict:
    return {
        "report_id": report_id,
        "agent_id": agent_id,
        "kind": "chargeback",
        "evidence_hash": evidence,
        "reporter_org_id": reporter,
        "excluded": False,
    }


def _score(reports: list[dict], context: ScoreContext) -> int:
    return trust_score(
        verification_level="operator_verified",
        operator_status="active",
        operator_org_id="org-operator",
        reports=reports,
        disputes=[],
        reporter_types={"org-merchant": "merchant", "org-a": "merchant", "org-b": "merchant", "org-c": "merchant"},
        policy=ScorePolicy(),
        context=context,
    )["score"]


def test_a_chargeback_that_contradicts_settled_activity_weighs_less():
    evidence = "sha256:" + "ab" * 32
    report = _chargeback("c1", "org-merchant", evidence)
    plain = ScoreContext(now="2026-10-15T00:00:00Z", reporter_created_at={"org-merchant": "2020-01-01T00:00:00Z"}, linked_reporters={"org-merchant"})
    mixed = ScoreContext(
        now=plain.now,
        reporter_created_at=dict(plain.reporter_created_at),
        linked_reporters={"org-merchant"},
        positive_pairs={("org-merchant", "shopper-01")},
    )
    assert _score([report], mixed) > _score([report], plain)


def test_a_reporter_aimed_at_one_operator_weighs_less():
    evidence = "sha256:" + "cd" * 32
    report = _chargeback("c1", "org-merchant", evidence)
    plain = ScoreContext(now="2026-10-15T00:00:00Z", reporter_created_at={"org-merchant": "2020-01-01T00:00:00Z"}, linked_reporters={"org-merchant"})
    clustered = ScoreContext(
        now=plain.now,
        reporter_created_at=dict(plain.reporter_created_at),
        linked_reporters={"org-merchant"},
        reporter_clusters={"org-merchant": {"negatives": 3, "operators": 1}},
    )
    assert _score([report], clustered) > _score([report], plain)


def test_reused_evidence_across_reporters_weighs_less():
    evidence = "sha256:" + "ef" * 32
    report = _chargeback("c1", "org-a", evidence)
    plain = ScoreContext(now="2026-10-15T00:00:00Z", reporter_created_at={"org-a": "2020-01-01T00:00:00Z"}, linked_reporters={"org-a"})
    copied = ScoreContext(
        now=plain.now,
        reporter_created_at={"org-a": "2020-01-01T00:00:00Z"},
        linked_reporters={"org-a"},
        evidence_reporters={evidence: 3},
    )
    assert _score([report], copied) > _score([report], plain)
