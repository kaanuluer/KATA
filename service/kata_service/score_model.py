# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Published weights for the agent score.

Risk is the complement of the score, 1000 minus the score. It is not a second
model. Individuals are not scored. GAB_SCORE_WEIGHTS can replace a weight for
calibration. The version string stays gab-score-1 unless that JSON sets another.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, replace

MODEL_VERSION = "gab-score-1"
_VERSION = re.compile(r"^[a-z0-9][a-z0-9._-]{0,40}$")


@dataclass(frozen=True)
class ScoreWeights:
    model_version: str = MODEL_VERSION
    baseline: int = 500
    unverified: int = 0
    key_bound: int = 40
    operator_established: int = 80
    operator_verified: int = 120
    institution_attested: int = 200
    operator_active: int = 80
    operator_inactive: int = -40
    fraud_incident: int = -120
    chargeback: int = -80
    policy_violation: int = -40
    settled: int = 8
    loss: int = -30
    bank_issuer: float = 1.0
    processor_psp: float = 1.0
    wallet: float = 0.8
    merchant: float = 0.7
    agent_operator: float = 0.4
    reporter_default: float = 0.5
    self_operator: float = 0.25

    def identity_points(self, level: str) -> int:
        return {
            "unverified": self.unverified,
            "key_bound": self.key_bound,
            "operator_established": self.operator_established,
            "operator_verified": self.operator_verified,
            "institution_attested": self.institution_attested,
        }.get(level, 0)

    def reporter_weight(self, org_type: str) -> float:
        return {
            "bank_issuer": self.bank_issuer,
            "processor_psp": self.processor_psp,
            "wallet": self.wallet,
            "merchant": self.merchant,
            "agent_operator": self.agent_operator,
        }.get(org_type, self.reporter_default)

    def report_base(self, kind: str, outcome: str) -> tuple[int, str]:
        if kind == "fraud_incident":
            return self.fraud_incident, "FRAUD_INCIDENT"
        if kind == "chargeback":
            return self.chargeback, "CHARGEBACK"
        if kind == "policy_violation":
            return self.policy_violation, "POLICY_VIOLATION"
        if kind == "transaction_outcome" and outcome == "settled":
            return self.settled, "SETTLED_ACTIVITY"
        if kind == "transaction_outcome" and outcome == "loss":
            return self.loss, "LOSS_ACTIVITY"
        return 0, "REPORT"

    def risk(self, score: int) -> int:
        return 1000 - int(score)

    def public(self) -> dict:
        return {
            "model_version": self.model_version,
            "subjects": "agents",
            "individuals_scored": False,
            "risk": "1000 - score",
            "baseline": self.baseline,
            "identity": {
            "unverified": self.unverified,
            "key_bound": self.key_bound,
            "operator_established": self.operator_established,
            "operator_verified": self.operator_verified,
            "institution_attested": self.institution_attested,
            },
            "operator_active": self.operator_active,
            "operator_inactive": self.operator_inactive,
            "reports": {
                "fraud_incident": self.fraud_incident,
                "chargeback": self.chargeback,
                "policy_violation": self.policy_violation,
                "settled": self.settled,
                "loss": self.loss,
            },
            "reporter_weights": {
                "bank_issuer": self.bank_issuer,
                "processor_psp": self.processor_psp,
                "wallet": self.wallet,
                "merchant": self.merchant,
                "agent_operator": self.agent_operator,
                "default": self.reporter_default,
            },
            "self_operator_multiplier": self.self_operator,
        }


def weights_from_json(raw: str | None) -> ScoreWeights:
    """Parse GAB_SCORE_WEIGHTS. Empty means the built-in gab-score-1 weights."""

    if raw is None or not str(raw).strip():
        return ScoreWeights()
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("GAB_SCORE_WEIGHTS is not JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError("GAB_SCORE_WEIGHTS must be a JSON object")
    updates: dict = {}
    identity = payload.get("identity")
    if identity is not None:
        if not isinstance(identity, dict):
            raise ValueError("GAB_SCORE_WEIGHTS identity must be an object")
        for level in ("unverified", "key_bound", "operator_established", "operator_verified", "institution_attested"):
            if level in identity:
                updates[level] = _bounded_int(identity[level], level, -500, 500)
    reporters = payload.get("reporter_weights")
    if reporters is not None:
        if not isinstance(reporters, dict):
            raise ValueError("GAB_SCORE_WEIGHTS reporter_weights must be an object")
        for name, field in (
            ("bank_issuer", "bank_issuer"),
            ("processor_psp", "processor_psp"),
            ("wallet", "wallet"),
            ("merchant", "merchant"),
            ("agent_operator", "agent_operator"),
            ("default", "reporter_default"),
        ):
            if name in reporters:
                updates[field] = _bounded_float(reporters[name], name, 0.0, 2.0)
    for name, low, high in (
        ("baseline", 0, 1000),
        ("operator_active", -500, 500),
        ("operator_inactive", -500, 500),
        ("fraud_incident", -500, 500),
        ("chargeback", -500, 500),
        ("policy_violation", -500, 500),
        ("settled", -500, 500),
        ("loss", -500, 500),
    ):
        if name in payload:
            updates[name] = _bounded_int(payload[name], name, low, high)
    if "self_operator_multiplier" in payload:
        updates["self_operator"] = _bounded_float(payload["self_operator_multiplier"], "self_operator_multiplier", 0.0, 1.0)
    version = payload.get("model_version")
    if version is not None:
        if not isinstance(version, str) or _VERSION.fullmatch(version) is None:
            raise ValueError("GAB_SCORE_WEIGHTS model_version is invalid")
        updates["model_version"] = version
    return replace(ScoreWeights(), **updates)


def _bounded_int(value: object, name: str, low: int, high: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"GAB_SCORE_WEIGHTS {name} must be an integer")
    if value < low or value > high:
        raise ValueError(f"GAB_SCORE_WEIGHTS {name} is outside {low}..{high}")
    return value


def _bounded_float(value: object, name: str, low: float, high: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"GAB_SCORE_WEIGHTS {name} must be a number")
    number = float(value)
    if number < low or number > high:
        raise ValueError(f"GAB_SCORE_WEIGHTS {name} is outside {low}..{high}")
    return number
