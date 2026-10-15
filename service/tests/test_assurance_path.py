# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""A cheaper assurance path for an established operator, and a settled cap that scales."""

from __future__ import annotations

import hashlib

from kata_intent import private_key_from_seed

from kata_service.bureau import trust_score
from kata_service.defenses import ScoreContext, ScorePolicy

from test_bureau import _auth, _client, _key, _org


def test_an_established_operator_scores_between_key_bound_and_operator_verified():
    client = _client()
    operator = _org(client, "Harbor Agents", "agent_operator")
    key = _key(client, operator["org_id"])
    client.app.state.bureau.repo.set_org_created_at(operator["org_id"], "2020-01-01T00:00:00Z")
    fresh = private_key_from_seed(hashlib.sha256(b"established-agent").digest())
    created = client.post(
        "/v1/agents",
        headers=_auth(key),
        json={
            "agent_id": "shopper-01",
            "principal_id": "prn_person",
            "public_key": fresh.public.to_jwk(),
            "verification_level": "operator_verified",
        },
    )
    assert created.status_code == 200, created.text
    body = created.json()
    assert body["assurance_level"] == "operator_established"
    assert body["score"] == 660


def test_settled_cap_grows_only_with_external_volume_and_diversity():
    reports = [
        {
            "report_id": f"s{index}",
            "kind": "transaction_outcome",
            "outcome": "settled",
            "evidence_hash": "sha256:" + f"{index:02x}" * 32,
            "reporter_org_id": f"org-{index}",
            "excluded": False,
        }
        for index in range(5)
    ]
    types = {f"org-{index}": "merchant" for index in range(5)}
    base = ScoreContext(
        now="2026-10-15T00:00:00Z",
        reporter_created_at={f"org-{index}": "2020-01-01T00:00:00Z" for index in range(5)},
        linked_reporters={f"org-{index}" for index in range(5)},
    )
    wide = ScoreContext(
        now=base.now,
        reporter_created_at=dict(base.reporter_created_at),
        linked_reporters=set(base.linked_reporters or set()),
        external_counterparties=3,
        external_volume=1000,
    )
    policy = ScorePolicy()
    narrow = trust_score(
        verification_level="key_bound",
        operator_status="active",
        operator_org_id="org-operator",
        reports=reports,
        disputes=[],
        reporter_types=types,
        policy=policy,
        context=base,
    )
    broader = trust_score(
        verification_level="key_bound",
        operator_status="active",
        operator_org_id="org-operator",
        reports=reports,
        disputes=[],
        reporter_types=types,
        policy=policy,
        context=wide,
    )
    assert narrow["score"] < broader["score"]
    assert broader["score"] - narrow["score"] == 5
