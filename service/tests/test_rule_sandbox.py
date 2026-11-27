# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Rule sandbox. Synthetic requests only. The flag defaults off.

The golden files are the POST /v1/verify bodies from #71. GAB_RULE_SANDBOX does
not change those bytes. The sandbox does not read a database and does not write
the ledger, evidence, or the live rule object.
"""

from __future__ import annotations

import hashlib
import io
import json
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import asdict

from fastapi.testclient import TestClient

from kata_service.asgi import create_app
from kata_service.decision_rationale import confidence_for
from kata_service.defenses import ScorePolicy
from kata_service.rule_sandbox import (
    DEFAULT_SEED,
    LIVE_RULES,
    MAX_BATCH,
    DecisionRules,
    SandboxError,
    generate_requests,
    live_rules,
    main,
    run_sandbox,
)
from kata_service.settings import Settings, settings_from_env
from kata_service.store import MemoryStore
from test_decision_rationale import CASES, FIXTURES, _case

_BATCH = (
    {
        "request_id": "low",
        "agent_status": "active",
        "agreement_count": 1,
        "amount": 10,
        "currency": "CAD",
        "action_type": "purchase",
        "score": 620,
        "cold_start": True,
    },
    {
        "request_id": "bound",
        "agent_status": "active",
        "agreement_count": 1,
        "amount": 100,
        "currency": "CAD",
        "action_type": "purchase",
        "score": 620,
        "cold_start": True,
    },
    {
        "request_id": "mid",
        "agent_status": "active",
        "agreement_count": 1,
        "amount": 800,
        "currency": "CAD",
        "action_type": "purchase",
        "score": 620,
        "cold_start": True,
    },
    {
        "request_id": "high",
        "agent_status": "active",
        "agreement_count": 1,
        "amount": 5000,
        "currency": "CAD",
        "action_type": "purchase",
        "score": 620,
        "cold_start": True,
    },
    {
        "request_id": "step",
        "agent_status": "active",
        "agreement_count": 2,
        "amount": 800,
        "currency": "CAD",
        "action_type": "purchase",
        "score": 620,
        "cold_start": True,
    },
    {
        "request_id": "down",
        "agent_status": "suspended",
        "agreement_count": 1,
        "amount": 10,
        "currency": "CAD",
        "action_type": "purchase",
        "score": 620,
        "cold_start": True,
    },
    {
        "request_id": "none",
        "agent_status": "active",
        "agreement_count": 0,
        "amount": 10,
        "currency": "CAD",
        "action_type": "purchase",
        "score": 620,
        "cold_start": True,
    },
)


def _settings(**overrides) -> Settings:
    base = dict(
        database_url=None,
        schema_url=None,
        log_signing_seed=hashlib.sha256(b"rule-sandbox-log").digest(),
        push_notifier_jwk=None,
        append_token=None,
        published_keys=(),
        fx_source_url="https://fx.test",
        admin_token="admin-test-token",
        rate_limit_per_minute=1000,
        verify_rate_limit_per_minute=1000,
    )
    base.update(overrides)
    return Settings(**base)


def _client(**overrides) -> TestClient:
    return TestClient(create_app(_settings(**overrides), MemoryStore()))


def _fingerprint(rules: DecisionRules) -> tuple:
    return (
        id(rules),
        rules.maximum_amount,
        rules.currency,
        rules.allowed_actions,
        id(rules.allowed_actions),
        rules.velocity_daily_count,
        rules.velocity_daily_amount,
        rules.velocity_enabled,
    )


def _policy_fingerprint() -> tuple:
    policy = ScorePolicy()
    return (policy.velocity, policy.velocity_daily_count, policy.velocity_daily_amount, policy.deny_score)


def _row(index: int, amount: int = 10) -> dict:
    return {
        "request_id": f"row-{index}",
        "agent_status": "active",
        "agreement_count": 1,
        "amount": amount,
        "currency": "CAD",
        "action_type": "purchase",
        "score": 620,
        "cold_start": True,
    }


class _Hostile(dict):
    """Candidate input that tries to replace the live rule object while it is read."""

    def __iter__(self):
        _attack()
        return dict.__iter__(self)

    def items(self):
        _attack()
        return dict.items(self)

    def __getitem__(self, key):
        _attack()
        return dict.__getitem__(self, key)


def _attack() -> None:
    import kata_service.rule_sandbox as sandbox

    target = sandbox.LIVE_RULES
    object.__setattr__(target, "maximum_amount", 1)
    object.__setattr__(target, "currency", "USD")
    object.__setattr__(target, "allowed_actions", ("transfer",))
    object.__setattr__(target, "velocity_daily_count", 1)
    object.__setattr__(target, "velocity_daily_amount", 1)
    object.__setattr__(target, "velocity_enabled", False)
    sandbox.LIVE_RULES = DecisionRules(1, "USD", ("transfer",), 1, 1, False)


def test_flag_defaults_off():
    assert settings_from_env({}).rule_sandbox is False
    assert settings_from_env({"GAB_RULE_SANDBOX": "0"}).rule_sandbox is False
    assert settings_from_env({"GAB_RULE_SANDBOX": "1"}).rule_sandbox is True
    assert settings_from_env({"GAB_RULE_SANDBOX": "yes"}).rule_sandbox is True
    assert live_rules().maximum_amount == 1500
    assert live_rules().velocity_daily_count == ScorePolicy().velocity_daily_count
    assert live_rules().velocity_daily_amount == ScorePolicy().velocity_daily_amount
    assert live_rules().velocity_enabled is ScorePolicy().velocity


def test_flag_off_matches_unknown_404_and_golden_verify_bytes():
    client = _client()
    assert client.app.state.settings.rule_sandbox is False
    unknown = client.post("/internal/not-a-real-route", json={"rules": {"maximum_amount": 1}})
    sandbox = client.post(
        "/internal/rule-sandbox",
        headers={"Authorization": "Bearer admin-test-token"},
        json={"rules": {"maximum_amount": 1}, "seed": DEFAULT_SEED},
    )
    assert sandbox.status_code == 404
    assert sandbox.content == unknown.content
    assert sandbox.headers["content-type"] == unknown.headers["content-type"]
    assert "/internal/rule-sandbox" not in client.get("/openapi.json").text
    for name, ready, body in CASES:
        _held, response = _case(name, ready, body)
        assert response.content == (FIXTURES / f"{name}.bin").read_bytes()
        assert _held.app.state.settings.rule_sandbox is False


def test_flag_on_leaves_verify_bytes_unchanged():
    for name, ready, body in CASES:
        _held, response = _case(name, ready, body, rule_sandbox=True)
        assert _held.app.state.settings.rule_sandbox is True
        assert response.content == (FIXTURES / f"{name}.bin").read_bytes()
        assert "/internal/rule-sandbox" in _held.get("/openapi.json").text


def test_identical_candidate_rules_have_zero_flips():
    explicit = {
        "maximum_amount": 1500,
        "currency": "CAD",
        "allowed_actions": ["purchase"],
        "velocity_daily_count": live_rules().velocity_daily_count,
        "velocity_daily_amount": live_rules().velocity_daily_amount,
        "velocity_enabled": True,
    }
    for rules in ({}, explicit):
        report = run_sandbox({"rules": rules, "requests": list(_BATCH)})
        assert report["flips"] == []
        assert report["changed"] == {"allow": 0, "deny": 0, "step_up": 0}
        assert report["counts"]["changed"] == report["changed"]
        assert report["counts"]["current"] == report["counts"]["candidate"]
        assert report["samples"]
        assert all(item["flipped"] is False for item in report["samples"])
    generated = run_sandbox({"seed": DEFAULT_SEED, "count": 24})
    assert generated["source"] == "generated"
    assert generated["flips"] == []
    assert generated["changed"] == {"allow": 0, "deny": 0, "step_up": 0}


def test_stricter_ceiling_flips_the_expected_decisions():
    report = run_sandbox({"rules": {"maximum_amount": 100}, "requests": list(_BATCH)})
    assert report["counts"]["current"] == {"allow": 3, "deny": 3, "step_up": 1}
    assert report["counts"]["candidate"] == {"allow": 2, "deny": 4, "step_up": 1}
    assert report["changed"] == {"allow": -1, "deny": 1, "step_up": 0}
    assert report["summary"] == (
        "7 synthetic requests from batch seed none. "
        "current allow 3 deny 3 step_up 1. "
        "candidate allow 2 deny 4 step_up 1. "
        "changed allow -1 deny 1 step_up 0. "
        "flips 1."
    )
    assert [item["request_id"] for item in report["flips"]] == ["mid"]
    flip = report["flips"][0]
    assert flip["current"]["verdict"] == "ALLOW"
    assert flip["current"]["reasons"] == []
    assert flip["candidate"]["verdict"] == "DENY"
    assert flip["candidate"]["kata_decision"] == "BLOCK"
    assert flip["candidate"]["reasons"] == ["AMOUNT_ABOVE_INTENT_CEILING", "ACTION_EXCEEDS_INTENT"]
    assert flip["rationale"]["candidate"]["reasons"] == flip["candidate"]["reasons"]
    assert flip["rationale"]["current"]["confidence"] == confidence_for("ALLOW", "ALLOW", [], 620, True, [])
    assert flip["rationale"]["candidate"]["confidence"] == confidence_for(
        "DENY",
        "BLOCK",
        ["AMOUNT_ABOVE_INTENT_CEILING", "ACTION_EXCEEDS_INTENT"],
        620,
        True,
        [],
    )
    by_id = {item["request_id"]: item for item in report["samples"]}
    assert by_id["bound"]["flipped"] is False
    assert by_id["bound"]["candidate"]["verdict"] == "ALLOW"
    assert by_id["step"]["flipped"] is False
    assert by_id["step"]["candidate"]["verdict"] == "STEP_UP"
    assert by_id["high"]["flipped"] is False
    assert by_id["mid"]["flipped"] is True
    assert report["rules"]["current"]["maximum_amount"] == 1500
    assert report["rules"]["candidate"]["maximum_amount"] == 100
    assert live_rules().maximum_amount == 1500


def test_confidence_is_omitted_without_a_score_and_uses_synthetic_evidence_only():
    body = {
        "rules": {"maximum_amount": 10},
        "requests": [
            {
                "request_id": "noscore",
                "agent_status": "active",
                "agreement_count": 1,
                "amount": 50,
                "currency": "CAD",
                "action_type": "purchase",
            }
        ],
    }
    report = run_sandbox(body)
    rationale = report["flips"][0]["rationale"]["candidate"]
    assert rationale["reasons"] == ["AMOUNT_ABOVE_INTENT_CEILING", "ACTION_EXCEEDS_INTENT"]
    assert "confidence" not in rationale
    marked = run_sandbox(
        {
            "rules": {},
            "requests": [
                {
                    "request_id": "marked",
                    "agent_status": "active",
                    "agreement_count": 1,
                    "amount": 10,
                    "currency": "CAD",
                    "action_type": "purchase",
                    "score": 620,
                    "cold_start": True,
                    "evidence_result": "invalid",
                }
            ],
        }
    )
    sample = marked["samples"][0]
    assert sample["flipped"] is False
    assert sample["rationale"]["current"]["confidence"] == confidence_for("ALLOW", "ALLOW", [], 620, True, ["invalid"])


def test_fixed_seed_is_deterministic():
    body = {"seed": DEFAULT_SEED, "count": 24, "rules": {"maximum_amount": 100}}
    first = run_sandbox(body)
    second = run_sandbox(dict(body))
    assert first == second
    assert first["seed"] == DEFAULT_SEED
    assert first["source"] == "generated"
    assert first["batch_size"] == 24
    assert generate_requests(DEFAULT_SEED, 24) == generate_requests(DEFAULT_SEED, 24)
    assert [item.request_id for item in generate_requests(DEFAULT_SEED, 3)] == ["syn-0000", "syn-0001", "syn-0002"]
    other = run_sandbox({"seed": DEFAULT_SEED + 1, "count": 24, "rules": {"maximum_amount": 100}})
    assert other["digest"] != first["digest"]
    raw = {key: value for key, value in first.items() if key != "digest"}
    encoded = json.dumps(raw, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    assert first["digest"] == hashlib.sha256(encoded.encode("utf-8")).hexdigest()
    assert first["samples"]
    assert len(first["samples"]) <= 8


def test_batch_size_limit_is_enforced():
    allowed = run_sandbox({"count": MAX_BATCH, "seed": 1})
    assert allowed["batch_size"] == MAX_BATCH
    try:
        run_sandbox({"count": MAX_BATCH + 1, "seed": 1})
    except SandboxError as exc:
        assert exc.message == f"batch is limited to {MAX_BATCH} requests"
    else:
        raise AssertionError("oversized count was accepted")
    oversized = [_row(index) for index in range(MAX_BATCH + 1)]
    try:
        run_sandbox({"requests": oversized})
    except SandboxError as exc:
        assert exc.message == f"batch is limited to {MAX_BATCH} requests"
    else:
        raise AssertionError("oversized batch was accepted")
    exact = run_sandbox({"requests": [_row(index) for index in range(MAX_BATCH)]})
    assert exact["batch_size"] == MAX_BATCH
    try:
        run_sandbox({"requests": [_row(1)], "count": 2})
    except SandboxError as exc:
        assert exc.message == "count does not match the batch"
    else:
        raise AssertionError("mismatched count was accepted")


def test_admin_auth_is_required_and_the_route_reports_counts():
    client = _client(rule_sandbox=True)
    missing = client.post("/internal/rule-sandbox", json={})
    assert missing.status_code == 401
    assert missing.json()["error"] == "admin credentials are required"
    wrong = client.post(
        "/internal/rule-sandbox",
        headers={"Authorization": "Bearer gab_test_not_admin"},
        json={},
    )
    assert wrong.status_code == 401
    assert wrong.json() == missing.json()
    closed = _client(rule_sandbox=True, admin_token=None)
    assert closed.post("/internal/rule-sandbox", json={}).status_code == 401
    ok = client.post(
        "/internal/rule-sandbox",
        headers={"Authorization": "Bearer admin-test-token"},
        json={"rules": {"maximum_amount": 100}, "requests": list(_BATCH)},
    )
    assert ok.status_code == 200
    assert ok.json() == run_sandbox({"rules": {"maximum_amount": 100}, "requests": list(_BATCH)})
    assert ok.json()["changed"] == {"allow": -1, "deny": 1, "step_up": 0}
    assert ok.json()["samples"]
    empty = client.post(
        "/internal/rule-sandbox",
        headers={"Authorization": "Bearer admin-test-token"},
        json={},
    )
    assert empty.status_code == 200
    assert empty.json()["flips"] == []
    not_json = client.post(
        "/internal/rule-sandbox",
        headers={"Authorization": "Bearer admin-test-token", "Content-Type": "application/json"},
        content=b"not-json",
    )
    assert not_json.status_code == 400
    assert not_json.json()["error"] == "sandbox body must be JSON"
    array = client.post(
        "/internal/rule-sandbox",
        headers={"Authorization": "Bearer admin-test-token"},
        json=["not", "an", "object"],
    )
    assert array.status_code == 400
    assert array.json()["error"] == "sandbox body must be a JSON object"


def test_live_rules_stay_identical_under_any_input():
    before = live_rules()
    before_fields = _fingerprint(before)
    before_policy = _policy_fingerprint()
    actions = ["purchase"]
    payloads = [
        {},
        {"rules": {}},
        {"rules": {"maximum_amount": 1}},
        {"rules": {"maximum_amount": 10, "ceiling": 99999}},
        {"rules": {"ceiling": 10, "maximum_amount": 10}},
        {"rules": {"__proto__": {"maximum_amount": 1}, "maximum_amount": 5}},
        {"rules": {"allowed_actions": actions}},
        {"database_url": "postgresql://prod.example/gab", "rules": {"maximum_amount": 1}},
        {"rules": {"maximum_amount": True}},
        {"rules": ["purchase"]},
        {"count": 10**9},
        {"seed": -1},
        {"requests": []},
        {"requests": [{"agent_id": "shopper-01", "action": {"amount": 10}}]},
        {"requests": [_row(1), _row(1)]},
        {"rules": {"maximum_amount": 0, "velocity_daily_amount": 0, "currency": "USD", "allowed_actions": []}},
        _Hostile(rules=_Hostile(maximum_amount=100, ceiling=1), requests=list(_BATCH)),
        _Hostile(),
    ]
    for payload in payloads:
        try:
            run_sandbox(payload)
        except (SandboxError, RuntimeError, TypeError):
            pass
        assert live_rules() is before
        assert _fingerprint(live_rules()) == before_fields
        assert _policy_fingerprint() == before_policy
    actions.append("transfer")
    assert live_rules().allowed_actions == ("purchase",)
    report = run_sandbox({"rules": {"maximum_amount": 100}, "requests": list(_BATCH)})
    report["rules"]["current"]["allowed_actions"].append("transfer")
    report["rules"]["candidate"]["maximum_amount"] = 1
    assert live_rules() is before
    assert _fingerprint(live_rules()) == before_fields

    client = _client(rule_sandbox=True)
    assert client.app.state.live_rules is before
    policy = client.app.state.settings.score_policy
    policy_before = asdict(policy)
    store = client.app.state.store
    assert store.snapshot() == ([], None)
    assert getattr(client.app.state, "bureau", None) is None
    hostile_http = [
        {"rules": {"maximum_amount": 1, "ceiling": 5000}},
        {"database_url": "postgresql://prod.example/gab"},
        {"requests": [{"agent_id": "real-agent", "action": {"amount": 1}}]},
        {"count": MAX_BATCH + 1},
        {"rules": {"maximum_amount": 100}, "requests": list(_BATCH)},
        {"rules": {"allowed_actions": ["purchase"], "velocity_enabled": False, "currency": "USD"}},
    ]
    for payload in hostile_http:
        client.post(
            "/internal/rule-sandbox",
            headers={"Authorization": "Bearer admin-test-token"},
            json=payload,
        )
        assert client.app.state.live_rules is before
        assert _fingerprint(client.app.state.live_rules) == before_fields
        assert client.app.state.settings.score_policy is policy
        assert asdict(client.app.state.settings.score_policy) == policy_before
        assert getattr(client.app.state, "bureau", None) is None
        assert store.snapshot() == ([], None)
        assert store.list_revocations() == []


def test_replay_does_not_write_ledger_evidence_or_database(monkeypatch):
    def boom(*_args, **_kwargs):
        raise AssertionError("sandbox touched a writer")

    monkeypatch.setattr("kata_service.agreement_ledger.append_allow", boom)
    monkeypatch.setattr("kata_service.evidence.attach.record_external_evidence", boom)
    monkeypatch.setattr("kata_service.store.open_store", boom)
    monkeypatch.setattr("psycopg.connect", boom)
    monkeypatch.setattr("builtins.open", boom)
    report = run_sandbox({"seed": DEFAULT_SEED, "count": 8, "rules": {"maximum_amount": 100}})
    assert report["batch_size"] == 8
    client = _client(rule_sandbox=True, database_url="postgresql://prod.example/gab")
    response = client.post(
        "/internal/rule-sandbox",
        headers={"Authorization": "Bearer admin-test-token"},
        json={"seed": 3, "count": 4, "rules": {"ceiling": 50}},
    )
    assert response.status_code == 200
    assert response.json()["source"] == "generated"
    assert getattr(client.app.state, "bureau", None) is None
    assert client.app.state.store.snapshot() == ([], None)


def test_cli_replays_synthetic_input_without_a_database(monkeypatch):
    def boom(*_args, **_kwargs):
        raise AssertionError("cli touched a writer")

    monkeypatch.setattr("psycopg.connect", boom)
    monkeypatch.setattr("kata_service.store.open_store", boom)
    out = io.StringIO()
    err = io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        status = main(["--seed", str(DEFAULT_SEED), "--count", "4", "--maximum-amount", "100"])
    assert status == 0
    assert err.getvalue() == ""
    report = json.loads(out.getvalue())
    assert report == run_sandbox({"seed": DEFAULT_SEED, "count": 4, "rules": {"maximum_amount": 100}})
    assert set(report["changed"]) == {"allow", "deny", "step_up"}
    assert report["samples"]
    again = io.StringIO()
    with redirect_stdout(again):
        assert main(["--seed", str(DEFAULT_SEED), "--count", "4", "--maximum-amount", "100"]) == 0
    assert json.loads(again.getvalue())["digest"] == report["digest"]
    limited = io.StringIO()
    with redirect_stderr(limited):
        assert main(["--count", str(MAX_BATCH + 1)]) == 2
    assert str(MAX_BATCH) in limited.getvalue()
    assert live_rules() is LIVE_RULES
    assert live_rules().maximum_amount == 1500
