# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Calibration hooks for the agent score. Risk is the complement of the score."""

from __future__ import annotations

from dataclasses import replace

from kata_service.bureau import trust_score
from kata_service.defenses import ScorePolicy
from kata_service.score_model import ScoreWeights
from kata_service.settings import settings_from_env

from test_bureau import _auth, _client, _key, _org, _register


def test_score_model_is_public_and_does_not_score_individuals():
    client = _client()
    published = client.get("/v1/score-model")
    assert published.status_code == 200, published.text
    body = published.json()
    assert body["model_version"] == "gab-score-1"
    assert body["subjects"] == "agents"
    assert body["individuals_scored"] is False
    assert body["risk"] == "1000 - score"
    assert body["reports"]["fraud_incident"] == -120
    assert body["identity"]["institution_attested"] == 200
    assert "credit bureau" not in published.text.lower()
    operator = _org(client, "Harbor Agents", "agent_operator")
    operator_key = _key(client, operator["org_id"])
    registered = _register(client, operator_key)
    assert registered["model_version"] == "gab-score-1"
    assert registered["risk"] == 1000 - registered["score"]


def test_weight_override_changes_a_bank_fraud_impact():
    scored = trust_score(
        verification_level="key_bound",
        operator_status="active",
        operator_org_id="org_op",
        reports=[
            {
                "report_id": "r1",
                "kind": "fraud_incident",
                "evidence_hash": "sha256:" + "cd" * 32,
                "reporter_org_id": "org_bank",
                "outcome": None,
                "excluded": False,
            }
        ],
        disputes=[],
        reporter_types={"org_bank": "bank_issuer"},
        policy=replace(ScorePolicy.legacy(), weights=replace(ScoreWeights(), fraud_incident=-100)),
    )
    fraud = [item for item in scored["reasons"] if item["code"] == "FRAUD_INCIDENT"]
    assert fraud[0]["points"] == -100
    assert scored["model_version"] == "gab-score-1"
    assert scored["risk"] == 1000 - scored["score"]
    parsed = settings_from_env({"GAB_SCORE_WEIGHTS": '{"fraud_incident": -90, "model_version": "gab-score-1"}'})
    assert parsed.config_error is None
    assert parsed.score_policy.weights.fraud_incident == -90
    client = _client(score_policy=parsed.score_policy)
    assert client.get("/v1/score-model").json()["reports"]["fraud_incident"] == -90


def test_bad_score_weights_are_a_configuration_error():
    assert settings_from_env({"GAB_SCORE_WEIGHTS": "{"}).config_error
    assert settings_from_env({"GAB_SCORE_WEIGHTS": '{"fraud_incident": -9000}'}).config_error
    assert settings_from_env({}).config_error is None
