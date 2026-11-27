# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Agent authority ladder. Synthetic agreements only. The flag defaults off.

An unassigned agent keeps the #71 verify bytes. A level never loosens a
decision. Stop applies to one agent and does not call the breach revoke.
"""

from __future__ import annotations

import hashlib
import inspect
from dataclasses import replace
from pathlib import Path

from kata_intent import Actor, Agreement, private_key_from_seed

from kata_service.agent_authority import (
    LEVELS,
    LIMITED_APPROVAL,
    LIMITED_CUMULATIVE,
    LIMITED_PER_TRANSACTION,
    REASON_APPROVAL,
    REASON_CUMULATIVE,
    REASON_OBSERVE,
    REASON_STEP_UP,
    REASON_STOPPED,
    REASON_TX,
    REASON_UNAVAILABLE,
    read_authority_level,
    effective_limits,
    tighter_or_equal,
)
from kata_service.audit_chain import AUDIT_CHAIN_START, audit_row_hash
from kata_service.bureau import BureauError, BureauService, MemoryRepo
from kata_service.bureau_pg import _MIGRATIONS, migration_sql
from kata_service.decision_rationale import confidence_for
from kata_service.rule_sandbox import DEFAULT_SEED, _baseline, _decide, generate_requests
from kata_service.settings import settings_from_env
from test_decision_rationale import (
    AT,
    CASES,
    EXPIRY,
    FIXTURES,
    _action,
    _auth,
    _case,
    _client,
    _keys,
    _ready,
    _verify,
)

PENDING = Path(__file__).resolve().parents[1] / "kata_service" / "migrations" / "pending" / "022_agent_authority.sql"
ADMIN = _auth("admin-test-token")


def test_flag_defaults_off():
    assert settings_from_env({}).agent_authority is False
    assert settings_from_env({"GAB_AGENT_AUTHORITY": "0"}).agent_authority is False
    assert settings_from_env({"GAB_AGENT_AUTHORITY": "1"}).agent_authority is True
    assert settings_from_env({"GAB_AGENT_AUTHORITY": "yes"}).agent_authority is True
    assert BureauService(MemoryRepo()).agent_authority is False


def test_flag_off_routes_match_unknown_404_and_golden_bytes():
    client = _client()
    assert client.app.state.settings.agent_authority is False
    unknown = client.post("/internal/not-a-real-route", json={"level": 0})
    for path in (
        "/internal/agent-authority/shopper-01/level",
        "/internal/agent-authority/shopper-01/stop",
        "/internal/agent-authority/shopper-01/resume",
    ):
        response = client.post(path, headers=ADMIN, json={"level": 0})
        assert response.status_code == 404
        assert response.content == unknown.content
        assert response.headers["content-type"] == unknown.headers["content-type"]
    assert "/internal/agent-authority" not in client.get("/openapi.json").text
    for name, ready, body in CASES:
        _held, response = _case(name, ready, body)
        assert response.content == (FIXTURES / f"{name}.bin").read_bytes()


def test_flag_off_ignores_a_stored_level_and_stop():
    client = _client()
    token = _ready(client)
    agent = client.app.state.bureau.repo.get_agent("shopper-01")
    assert agent is not None
    agent["authority_level"] = 0
    agent["authority_stopped"] = True
    client.app.state.bureau.repo.save_agent(agent)
    response = _verify(client, token, {"agent_id": "shopper-01", "action": _action("act_allow")})
    assert response.content == (FIXTURES / "allow.bin").read_bytes()


def test_flag_on_unassigned_and_level_3_match_golden_bytes():
    for name, ready, body in CASES:
        _held, response = _case(name, ready, body, agent_authority=True)
        assert _held.app.state.settings.agent_authority is True
        assert response.content == (FIXTURES / f"{name}.bin").read_bytes()
        client = _client(agent_authority=True)
        token = _ready(client, **ready)
        assigned = client.post(
            "/internal/agent-authority/shopper-01/level",
            headers=ADMIN,
            json={"level": 3},
        )
        assert assigned.status_code == 200, assigned.text
        assert assigned.json()["level"] == 3
        leveled = _verify(client, token, body)
        assert leveled.content == (FIXTURES / f"{name}.bin").read_bytes()


def test_admin_bearer_is_required():
    client = _client(agent_authority=True)
    token = _ready(client)
    path = "/internal/agent-authority/shopper-01/stop"
    assert client.post(path).status_code == 401
    assert client.post(path, headers=_auth("not-the-admin")).status_code == 401
    operator = client.post(path, headers=_auth(token))
    assert operator.status_code == 401
    assert operator.json()["error"] == "admin credentials are required"
    assert client.post(path, json={"level": True}, headers=ADMIN).status_code == 200
    bad = client.post(
        "/internal/agent-authority/shopper-01/level",
        headers=ADMIN,
        json={"level": True},
    )
    assert bad.status_code == 400
    assert client.post(
        "/internal/agent-authority/shopper-01/level",
        headers=ADMIN,
        json={"level": 4},
    ).status_code == 400


def test_each_level_and_the_approval_threshold():
    observe = _decide_http(0, _action("act_observe", amount=10))
    assert observe["verdict"] == "DENY"
    assert observe["reasons"] == [REASON_OBSERVE]
    step = _decide_http(1, _action("act_step_only", amount=10))
    assert step["verdict"] == "STEP_UP"
    assert step["kata_decision"] == "STEP_UP"
    assert step["reasons"] == [REASON_STEP_UP]
    assert step["required_action"] == "HUMAN_APPROVAL"
    held = _decide_http(1, _action("act_still_denied", amount=5000))
    assert held["verdict"] == "DENY"
    assert "AMOUNT_ABOVE_INTENT_CEILING" in held["reasons"]
    low = _decide_http(2, _action("act_low", amount=10))
    assert low["verdict"] == "ALLOW"
    assert low["reasons"] == []
    approval = _decide_http(2, _action("act_approval", amount=LIMITED_APPROVAL + 1))
    assert approval["verdict"] == "STEP_UP"
    assert approval["reasons"] == [REASON_APPROVAL]
    assert approval["required_action"] == "HUMAN_APPROVAL"
    hard = _decide_http(2, _action("act_hard", amount=LIMITED_PER_TRANSACTION + 1))
    assert hard["verdict"] == "DENY"
    assert hard["reasons"] == [REASON_TX]
    already = _decide_http(2, _action("act_ceiling", amount=5000))
    assert already["verdict"] == "DENY"
    assert already["reasons"][0] == "AMOUNT_ABOVE_INTENT_CEILING"


def test_level_limits_never_exceed_the_agents_intent_or_agreement():
    for level in LEVELS:
        for intent, cumulative in ((1500, 2000), (40, 30), (10, 10), (0, 0)):
            limits = effective_limits(level, intent, cumulative)
            assert limits.per_transaction is not None
            assert limits.cumulative is not None
            assert limits.per_transaction <= intent
            assert limits.cumulative <= cumulative
            if limits.approval is not None:
                assert limits.approval <= limits.per_transaction
                assert limits.approval <= cumulative
    limited = effective_limits(2, 40, 30)
    assert limited.per_transaction == 40
    assert limited.cumulative == 30
    assert limited.approval == LIMITED_APPROVAL
    assert limited.per_transaction < LIMITED_PER_TRANSACTION
    assert limited.cumulative < LIMITED_CUMULATIVE
    standard = effective_limits(3, 40, 30)
    assert standard.per_transaction == 40
    assert standard.cumulative == 30
    assert standard.approval is None

    client = _client(agent_authority=True)
    token = _ready(client, agreements=0)
    _store(client, token, "shopper-01", _keys()[1], "agr_tight", "int_tight", 40, 30)
    assert client.post("/internal/agent-authority/shopper-01/level", headers=ADMIN, json={"level": 2}).status_code == 200
    over_intent = _verify(client, token, {"agent_id": "shopper-01", "action": _action("act_over_intent", amount=50)}).json()
    assert over_intent["verdict"] == "DENY"
    assert "AMOUNT_ABOVE_INTENT_CEILING" in over_intent["reasons"]
    assert over_intent["reasons"] != [REASON_TX]
    inside = _verify(client, token, {"agent_id": "shopper-01", "action": _action("act_inside", amount=30)}).json()
    assert inside["verdict"] == "STEP_UP"
    assert inside["reasons"] == [REASON_APPROVAL]
    allowed = _verify(client, token, {"agent_id": "shopper-01", "action": _action("act_fit", amount=20)}).json()
    assert allowed["verdict"] == "ALLOW"


def test_level_2_cumulative_is_tighter_than_the_agreement():
    amounts = [LIMITED_APPROVAL] * 4 + [LIMITED_APPROVAL]
    limited = _charge_sequence(2, amounts, "cap")
    assert [item["verdict"] for item in limited[:4]] == ["ALLOW", "ALLOW", "ALLOW", "ALLOW"]
    assert limited[4]["verdict"] == "DENY"
    assert limited[4]["reasons"] == [REASON_CUMULATIVE]
    current = _charge_sequence(3, amounts, "open")
    assert [item["verdict"] for item in current] == ["ALLOW", "ALLOW", "ALLOW", "ALLOW", "ALLOW"]


def test_results_are_never_looser_than_level_3():
    for name, ready, body in CASES:
        client = _client(agent_authority=True)
        token = _ready(client, **ready)
        baseline = _verify(client, token, _retitled(body, "base")).json()
        for level in LEVELS:
            other = _client(agent_authority=True)
            other_token = _ready(other, **ready)
            assert other.post(
                "/internal/agent-authority/shopper-01/level",
                headers=ADMIN,
                json={"level": level},
            ).status_code == 200
            got = _verify(other, other_token, _retitled(body, f"L{level}")).json()
            assert tighter_or_equal(got["verdict"], baseline["verdict"])
            if level == 3:
                assert got["verdict"] == baseline["verdict"]
                assert got["reasons"] == baseline["reasons"]
    rules = _baseline()
    for seed in (0, DEFAULT_SEED, 99):
        for request in generate_requests(seed, 24):
            baseline = _decide(rules, request)
            for level in LEVELS:
                got = _decide(rules, replace(request, authority_level=level))
                assert tighter_or_equal(got["verdict"], baseline["verdict"])


def test_stop_then_resume_and_agent_b_still_allows():
    client = _client(agent_authority=True)
    token = _ready(client)
    _second_agent(client, token)
    before = client.post("/internal/breach/revoke", headers=ADMIN)
    assert before.status_code == 404
    stopped = client.post("/internal/agent-authority/shopper-01/stop", headers=ADMIN)
    assert stopped.status_code == 200, stopped.text
    assert stopped.json()["stopped"] is True
    denied = _verify(client, token, {"agent_id": "shopper-01", "action": _action("act_a_stopped")}).json()
    assert denied["verdict"] == "DENY"
    assert denied["reasons"] == [REASON_STOPPED]
    other = _verify(client, token, {"agent_id": "shopper-02", "action": _action("act_b_open", amount=10)}).json()
    assert other["verdict"] == "ALLOW"
    assert other["reasons"] == []
    after = client.post("/internal/breach/revoke", headers=ADMIN)
    assert after.status_code == 404
    assert after.content == before.content
    assert all(not item.get("revoked_at") for item in client.app.state.bureau.repo.keys.values())
    resumed = client.post("/internal/agent-authority/shopper-01/resume", headers=ADMIN)
    assert resumed.status_code == 200, resumed.text
    assert resumed.json()["stopped"] is False
    restored = _verify(client, token, {"agent_id": "shopper-01", "action": _action("act_a_back")}).json()
    assert restored["verdict"] == "ALLOW"
    still = _verify(client, token, {"agent_id": "shopper-02", "action": _action("act_b_still")}).json()
    assert still["verdict"] == "ALLOW"


def test_stop_does_not_call_breach_revoke():
    import kata_service.agent_authority as authority
    import kata_service.bureau as bureau

    blob = "\n".join(
        (
            inspect.getsource(authority),
            inspect.getsource(bureau.BureauService.stop_agent),
            inspect.getsource(bureau.BureauService.resume_agent),
            inspect.getsource(bureau.BureauService.set_authority_level),
            inspect.getsource(bureau.BureauService._write_authority),
            inspect.getsource(bureau.BureauService._authority_audit),
        )
    )
    lowered = blob.lower()
    assert "breach" not in lowered
    assert "revoke_live_credentials" not in blob
    assert "revoke_credentials" not in blob
    assert "gab_breach" not in lowered


def test_level_stop_and_resume_keep_the_audit_chain():
    client = _client(agent_authority=True)
    token = _ready(client)
    assert client.post(
        "/internal/agent-authority/shopper-01/level",
        headers=ADMIN,
        json={"level": 1},
    ).status_code == 200
    assert client.post("/internal/agent-authority/shopper-01/stop", headers=ADMIN).status_code == 200
    assert client.post("/internal/agent-authority/shopper-01/resume", headers=ADMIN).status_code == 200
    denied = _verify(client, token, {"agent_id": "shopper-01", "action": _action("act_while", amount=10)})
    assert denied.json()["verdict"] == "STEP_UP"
    repo = client.app.state.bureau.repo
    chain = repo.audit_chain()
    assert chain["ok"] is True
    assert chain["rows"] == len(repo.audit)
    paths = [row["path"] for row in repo.audit]
    events = [
        "/internal/agent-authority/shopper-01/level",
        "/internal/agent-authority/shopper-01/stop",
        "/internal/agent-authority/shopper-01/resume",
    ]
    indexes = [paths.index(path) for path in events]
    assert indexes == sorted(indexes)
    prev = AUDIT_CHAIN_START
    for row in repo.audit:
        assert row["prev_hash"] == prev
        assert row["hash"] == audit_row_hash(prev, row)
        prev = row["hash"]
    target = next(row for row in repo.audit if row["path"].endswith("/stop"))
    target["path"] = "/internal/agent-authority/shopper-01/tampered"
    broken = repo.audit_chain()
    assert broken["ok"] is False
    assert broken["break"] == "hash does not match the row"


def test_rationale_includes_the_authority_reason():
    client = _client(agent_authority=True, decision_rationale=True)
    token = _ready(client)
    assert client.post(
        "/internal/agent-authority/shopper-01/level",
        headers=ADMIN,
        json={"level": 1},
    ).status_code == 200
    payload = _verify(client, token, {"agent_id": "shopper-01", "action": _action("act_why")}).json()
    assert payload["reasons"] == [REASON_STEP_UP]
    assert payload["rationale"]["reasons"] == payload["reasons"]
    agent = client.app.state.bureau.repo.get_agent("shopper-01")
    assert agent is not None
    assert payload["rationale"]["confidence"] == confidence_for(
        "STEP_UP",
        "STEP_UP",
        [REASON_STEP_UP],
        int(agent["score"]),
        bool(agent["cold_start"]),
        [],
    )


def test_apply_failure_fails_closed_below_level_3(monkeypatch):
    def boom(*_args, **_kwargs):
        raise RuntimeError("authority apply failed")

    monkeypatch.setattr("kata_service.agent_authority.apply_authority", boom)
    client = _client(agent_authority=True)
    token = _ready(client)
    unchanged = _verify(client, token, {"agent_id": "shopper-01", "action": _action("act_allow")})
    assert unchanged.content == (FIXTURES / "allow.bin").read_bytes()
    for level in (0, 1, 2):
        held = _client(agent_authority=True)
        held_token = _ready(held)
        assert held.post(
            "/internal/agent-authority/shopper-01/level",
            headers=ADMIN,
            json={"level": level},
        ).status_code == 200
        body = _verify(held, held_token, {"agent_id": "shopper-01", "action": _action(f"act_fail_{level}")}).json()
        assert body["verdict"] != "ALLOW"
        assert body["reasons"] == [REASON_UNAVAILABLE]
        if level == 0:
            assert body["verdict"] == "DENY"
            assert body["kata_decision"] == "BLOCK"
        else:
            assert body["verdict"] == "STEP_UP"


def test_level_read_failure_steps_up(monkeypatch):
    def boom(_agent):
        raise RuntimeError("authority level was not read")

    monkeypatch.setattr("kata_service.agent_authority.read_authority_level", boom)
    client = _client(agent_authority=True)
    token = _ready(client)
    body = _verify(client, token, {"agent_id": "shopper-01", "action": _action("act_unread")}).json()
    assert body["verdict"] == "STEP_UP"
    assert body["kata_decision"] == "STEP_UP"
    assert body["reasons"] == [REASON_UNAVAILABLE]


def test_missing_authority_column_stays_unassigned():
    from kata_service.bureau_pg import _agent_row

    row = (
        "shopper-01",
        "org_synthetic",
        "prn_person",
        "active",
        "operator_verified",
        "EdDSA",
        "ab" * 32,
        '{"kty":"OKP","crv":"Ed25519","x":"abc"}',
        "2026-10-04T13:55:00Z",
        "2026-10-04T13:55:00Z",
        0,
        "[]",
        1,
        None,
        False,
        None,
    )
    agent = _agent_row(row)
    assert "authority_level" not in agent
    assert "authority_stopped" not in agent
    assert read_authority_level(agent) is None
    service = BureauService(MemoryRepo(), agent_authority=True)
    payload = {"verdict": "ALLOW", "kata_decision": "ALLOW", "reasons": [], "messages": []}

    def boom(*_args, **_kwargs):
        raise RuntimeError("authority apply failed")

    service_module = __import__("kata_service.agent_authority", fromlist=["apply_authority"])
    original = service_module.apply_authority
    service_module.apply_authority = boom
    try:
        result = service._apply_authority(agent, {"amount": 10, "currency": "CAD"}, payload, None)
    finally:
        service_module.apply_authority = original
    assert result is payload
    assert result["verdict"] == "ALLOW"
    assert result["reasons"] == []


def test_missing_column_reports_not_available_and_verify_does_not_crash():
    client = _client(agent_authority=True)
    token = _ready(client)

    def unavailable(_record):
        raise BureauError(503, "agent authority is not available")

    client.app.state.bureau.repo.save_agent_authority = unavailable
    response = client.post(
        "/internal/agent-authority/shopper-01/level",
        headers=ADMIN,
        json={"level": 1},
    )
    assert response.status_code == 503
    assert response.json()["error"] == "agent authority is not available"
    allowed = _verify(client, token, {"agent_id": "shopper-01", "action": _action("act_allow")})
    assert allowed.content == (FIXTURES / "allow.bin").read_bytes()
    assert "authority_level" not in migration_sql()
    assert "022_agent_authority.sql" not in {path.name for path in _MIGRATIONS.glob("*.sql")}
    text = PENDING.read_text(encoding="utf-8")
    assert "ADD COLUMN IF NOT EXISTS authority_level" in text
    assert "ADD COLUMN IF NOT EXISTS authority_stopped" in text
    assert "not on the boot path" in text


def _decide_http(level: int, action: dict) -> dict:
    client = _client(agent_authority=True)
    token = _ready(client)
    assert client.post(
        "/internal/agent-authority/shopper-01/level",
        headers=ADMIN,
        json={"level": level},
    ).status_code == 200
    return _verify(client, token, {"agent_id": "shopper-01", "action": action}).json()


def _charge_sequence(level: int, amounts: list[int], prefix: str) -> list[dict]:
    client = _client(agent_authority=True)
    token = _ready(client)
    assert client.post(
        "/internal/agent-authority/shopper-01/level",
        headers=ADMIN,
        json={"level": level},
    ).status_code == 200
    results = []
    for index, amount in enumerate(amounts):
        results.append(
            _verify(
                client,
                token,
                {"agent_id": "shopper-01", "action": _action(f"{prefix}_{index}", amount=amount)},
            ).json()
        )
    return results


def _retitled(body: dict, action_id: str) -> dict:
    action = dict(body["action"])
    action["action_id"] = action_id
    updated = dict(body)
    updated["action"] = action
    return updated


def _store(client, token: str, agent_id: str, agent_key, agreement_id: str, intent_id: str, maximum: int, cumulative: int) -> None:
    agreement = _signed(agent_key, agent_id, agreement_id, intent_id, maximum, cumulative)
    stored = client.post(
        f"/v1/agents/{agent_id}/intents",
        headers={**_auth(token), "Content-Type": "application/json"},
        content=agreement.to_json(),
    )
    assert stored.status_code == 200, stored.text


def _second_agent(client, token: str) -> None:
    agent_key = private_key_from_seed(hashlib.sha256(b"authority-agent-b").digest())
    registered = client.post(
        "/v1/agents",
        headers=_auth(token),
        json={
            "agent_id": "shopper-02",
            "principal_id": "prn_person",
            "public_key": agent_key.public.to_jwk(),
            "verification_level": "operator_verified",
        },
    )
    assert registered.status_code == 200, registered.text
    _store(client, token, "shopper-02", agent_key, "agr_other_agent", "int_other_agent", 1500, 2000)


def _signed(agent_key, agent_id: str, agreement_id: str, intent_id: str, maximum: int, cumulative: int):
    principal, _default_agent = _keys()
    agreement = Agreement.propose(
        agreement_id=agreement_id,
        principal={"display_name": "A Principal", "id": "prn_person", "type": "human"},
        agent={"agent_id": agent_id},
        agent_public_key=agent_key.public,
        intent={
            "allowed_actions": ["purchase"],
            "currency": "CAD",
            "intent_id": intent_id,
            "maximum_amount": maximum,
            "purpose": "purchase",
            "time_limit": EXPIRY,
            "version": 1,
        },
        limits={"cumulative_maximum": cumulative},
        parent_limits={"cumulative_maximum": cumulative, "currency": "CAD", "maximum_amount": maximum},
        actor=Actor("agent", agent_id),
        at=AT,
        expires_at=EXPIRY,
    )
    agreement.accept(principal, AT, confirmed_text=agreement.rendering_preview())
    return agreement
