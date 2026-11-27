# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Human hold queue. Synthetic agreements only. The flag defaults off.

An unheld verify keeps the #71 bytes. A hold is one approval, bound to the
original decision. It is not a case file.
"""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path

from kata_service.audit_chain import audit_row_hash
from kata_service.bureau import BureauService, MemoryRepo
from kata_service.bureau_pg import _MIGRATIONS, migration_sql
from kata_service.hold_queue import (
    REASON_EXPIRED,
    REASON_UNAVAILABLE,
    binding_failure,
    hold_unavailable_decision,
)
from kata_service.settings import settings_from_env
from test_decision_rationale import (
    FIXTURES,
    FROZEN,
    _action,
    _auth,
    _case,
    _client,
    _ready,
    _verify,
)
from test_agent_authority import ADMIN

PENDING = Path(__file__).resolve().parents[1] / "kata_service" / "migrations" / "pending" / "023_hold_queue.sql"
REVIEWER = "rev_ada"
OTHER_REVIEWER = "rev_boa"


def test_flag_defaults_off_and_the_migration_is_not_on_the_boot_path():
    assert settings_from_env({}).hold_queue is False
    assert settings_from_env({"GAB_HOLD_QUEUE": "0"}).hold_queue is False
    assert settings_from_env({"GAB_HOLD_QUEUE": "1"}).hold_queue is True
    assert settings_from_env({"GAB_HOLD_QUEUE": "yes"}).hold_queue is True
    assert settings_from_env({}).hold_ttl_seconds == 900
    assert settings_from_env({"GAB_HOLD_TTL_SECONDS": "120"}).hold_ttl_seconds == 120
    assert BureauService(MemoryRepo()).hold_queue is False
    assert "023_hold_queue.sql" not in {path.name for path in _MIGRATIONS.glob("*.sql")}
    assert "gab_holds" not in migration_sql()
    text = PENDING.read_text(encoding="utf-8")
    assert "CREATE TABLE IF NOT EXISTS gab_holds" in text
    assert "decision_ref" in text
    assert "payload_hash" in text
    assert "reviewer_id" in text
    assert "not on the boot path" in text


def test_flag_off_routes_match_unknown_404_and_golden_bytes():
    client = _client()
    assert client.app.state.settings.hold_queue is False
    unknown = client.post("/internal/not-a-real-route", json={"reviewer_id": REVIEWER, "reason": "no"})
    for path in (
        "/internal/holds/hold_example/approve",
        "/internal/holds/hold_example/reject",
    ):
        response = client.post(path, headers=ADMIN, json={"reviewer_id": REVIEWER, "reason": "no"})
        assert response.status_code == 404
        assert response.content == unknown.content
        assert response.headers["content-type"] == unknown.headers["content-type"]
    unknown_get = client.get("/internal/not-a-real-route")
    listed = client.get("/internal/holds", headers=ADMIN)
    assert listed.status_code == 404
    assert listed.content == unknown_get.content
    assert listed.headers["content-type"] == unknown_get.headers["content-type"]
    document = client.get("/openapi.json").text
    assert "/internal/holds" not in document
    for name, ready, body in _cases():
        _held, response = _case(name, ready, body)
        assert response.content == (FIXTURES / f"{name}.bin").read_bytes()


def test_flag_on_allow_and_deny_match_golden_bytes_and_step_up_gains_only_hold_id():
    for name, ready, body in _cases():
        if name == "step_up":
            continue
        _held, response = _case(name, ready, body, hold_queue=True)
        assert _held.app.state.settings.hold_queue is True
        assert response.content == (FIXTURES / f"{name}.bin").read_bytes()
    client, response = _case("step_up", {"agreements": 2}, {"agent_id": "shopper-01", "action": _action("act_step")}, hold_queue=True)
    payload = response.json()
    hold_id = payload.pop("hold_id")
    assert hold_id.startswith("hold_")
    assert payload == json.loads((FIXTURES / "step_up.bin").read_text(encoding="utf-8"))
    assert response.json()["verdict"] == "STEP_UP"
    listed = client.get("/internal/holds", headers=ADMIN)
    assert listed.status_code == 200, listed.text
    assert listed.json()["holds"][0]["hold_id"] == hold_id
    assert listed.json()["holds"][0]["decision_ref"]
    assert listed.json()["holds"][0]["payload_hash"]
    assert "/internal/holds" in client.get("/openapi.json").text


def test_admin_bearer_is_required():
    client = _client(hold_queue=True)
    token = _ready(client, agreements=2)
    created = _verify(client, token, {"agent_id": "shopper-01", "action": _action("act_step")}).json()
    path = f"/internal/holds/{created['hold_id']}/approve"
    assert client.post(path, json={"reviewer_id": REVIEWER, "reason": "because"}).status_code == 401
    assert client.post(path, headers=_auth("not-the-admin"), json={"reviewer_id": REVIEWER, "reason": "because"}).status_code == 401
    operator = client.post(path, headers=_auth(token), json={"reviewer_id": REVIEWER, "reason": "because"})
    assert operator.status_code == 401
    assert operator.json()["error"] == "admin credentials are required"
    assert client.get("/internal/holds").status_code == 401
    assert client.post(path, headers=ADMIN, json={}).status_code == 400
    assert client.post(path, headers=ADMIN, json={"reviewer_id": REVIEWER}).status_code == 400
    assert client.post(path, headers=ADMIN, json={"reason": "because"}).status_code == 400
    approved = _approve(client, created["hold_id"])
    assert approved.status_code == 200, approved.text
    assert approved.json()["reviewer_id"] == REVIEWER
    assert approved.json()["reason"] == "customer confirmed"


def test_hold_lifecycle_approve_reject_conflict_and_expiry():
    client = _client(hold_queue=True, hold_ttl_seconds=60)
    token = _ready(client, agreements=2)
    first = _verify(client, token, {"agent_id": "shopper-01", "action": _action("act_one")}).json()
    second = _verify(client, token, {"agent_id": "shopper-01", "action": _action("act_two")}).json()
    third = _verify(client, token, {"agent_id": "shopper-01", "action": _action("act_three")}).json()
    assert len(client.get("/internal/holds", headers=ADMIN).json()["holds"]) == 3
    approved = _approve(client, first["hold_id"], reviewer=REVIEWER)
    assert approved.status_code == 200, approved.text
    assert approved.json()["status"] == "approved"
    assert approved.json()["decision_ref"] == client.app.state.bureau.repo.get_hold(first["hold_id"])["decision_ref"]
    again = _approve(client, first["hold_id"], reviewer=REVIEWER)
    assert again.status_code == 409
    assert again.json()["error"] == "hold is already decided"
    crossed = _reject(client, first["hold_id"])
    assert crossed.status_code == 409
    stored = client.app.state.bureau.repo.get_hold(first["hold_id"])
    assert stored["status"] == "approved"
    assert stored["reviewer_id"] == REVIEWER
    rejected = _reject(client, second["hold_id"], reviewer=OTHER_REVIEWER, reason="not this payment")
    assert rejected.status_code == 200, rejected.text
    assert rejected.json()["status"] == "rejected"
    assert rejected.json()["reviewer_id"] == OTHER_REVIEWER
    assert _approve(client, second["hold_id"]).status_code == 409
    assert _reject(client, second["hold_id"]).status_code == 409
    pending = client.get("/internal/holds", headers=ADMIN).json()["holds"]
    assert [item["hold_id"] for item in pending] == [third["hold_id"]]
    later = FROZEN + timedelta(seconds=61)
    client.app.state.bureau._now = lambda later=later: later
    expired = _verify(client, token, {"agent_id": "shopper-01", "action": _action("act_three")})
    assert expired.json()["verdict"] == "DENY"
    assert expired.json()["verdict"] != "ALLOW"
    assert expired.json()["reasons"] == [REASON_EXPIRED]
    assert expired.json()["kata_decision"] == "BLOCK"
    late = _approve(client, third["hold_id"])
    assert late.status_code == 409
    fresh = _client(hold_queue=True, hold_ttl_seconds=60)
    fresh_token = _ready(fresh, agreements=2)
    held = _verify(fresh, fresh_token, {"agent_id": "shopper-01", "action": _action("act_late")}).json()
    fresh_later = FROZEN + timedelta(seconds=61)
    fresh.app.state.bureau._now = lambda fresh_later=fresh_later: fresh_later
    decided = _approve(fresh, held["hold_id"])
    assert decided.status_code == 200, decided.text
    assert decided.json()["verdict"] == "DENY"
    assert decided.json()["reasons"] == [REASON_EXPIRED]
    assert decided.json()["verdict"] != "ALLOW"


def test_second_approval_and_replay_of_a_used_approval_are_rejected():
    client, token, action, hold_id = _approved_release()
    second = _approve(client, hold_id)
    assert second.status_code == 409
    assert second.json()["error"] == "hold is already decided"
    assert client.app.state.bureau.repo.get_hold(hold_id)["status"] == "approved"
    released = _use(client, token, action, hold_id)
    assert released.status_code == 200, released.text
    assert released.json()["verdict"] == "ALLOW"
    replay = _use(client, token, action, hold_id)
    assert replay.status_code == 409
    assert replay.json()["error"] == "approval was already used"
    assert replay.json().get("verdict") != "ALLOW"
    assert _approve(client, hold_id).status_code == 409


def test_binding_rejects_a_different_amount():
    client, token, action, hold_id = _approved_release(action_id="act_amount")
    changed = _action("act_amount", amount=11)
    _assert_binding_rejected(client, token, hold_id, changed, "amount")


def test_binding_rejects_a_different_payee():
    client, token, action, hold_id = _approved_release(action_id="act_payee")
    changed = _action("act_payee", amount=action["amount"])
    changed["context"] = {**changed["context"], "merchant": "other.example"}
    changed["parameters"] = {**changed["parameters"], "merchant": "other.example"}
    _assert_binding_rejected(client, token, hold_id, changed, "payee")


def test_binding_rejects_any_other_payload_change():
    client, token, action, hold_id = _approved_release(action_id="act_item")
    changed = _action("act_item", amount=action["amount"])
    changed["item"] = "Mouse"
    _assert_binding_rejected(client, token, hold_id, changed, "payload")


def test_release_denies_when_the_agent_was_stopped():
    client, token, action, hold_id = _approved_release(action_id="act_stopped")
    stopped = client.post("/internal/agent-authority/shopper-01/stop", headers=ADMIN)
    assert stopped.status_code == 200, stopped.text
    released = _use(client, token, action, hold_id)
    assert released.status_code == 200, released.text
    assert released.json()["verdict"] == "DENY"
    assert released.json()["verdict"] != "ALLOW"
    assert released.json()["reasons"] == ["AGENT_STOPPED"]


def test_release_denies_when_a_limit_is_exceeded():
    client = _client(hold_queue=True, agent_authority=True)
    token = _ready(client)
    assert client.post("/internal/agent-authority/shopper-01/level", headers=ADMIN, json={"level": 2}).status_code == 200
    action = _action("act_limit", amount=40)
    created = _verify(client, token, {"agent_id": "shopper-01", "action": action}).json()
    assert created["verdict"] == "STEP_UP"
    assert created["reasons"] == ["AUTHORITY_APPROVAL_REQUIRED"]
    assert _approve(client, created["hold_id"]).status_code == 200
    for index in range(3):
        booked = _verify(client, token, {"agent_id": "shopper-01", "action": _action(f"act_spent_{index}", amount=25)})
        assert booked.json()["verdict"] == "ALLOW"
    released = _use(client, token, action, created["hold_id"])
    assert released.status_code == 200, released.text
    assert released.json()["verdict"] == "DENY"
    assert released.json()["verdict"] != "ALLOW"
    assert "AUTHORITY_CUMULATIVE_LIMIT" in released.json()["reasons"]


def test_store_error_is_step_up_and_never_allow():
    calls: list[str] = []

    def boom(*_args, **_kwargs):
        calls.append("insert")
        raise RuntimeError("store down")

    quiet = _client(hold_queue=True)
    quiet_token = _ready(quiet)
    quiet.app.state.bureau.repo.insert_hold = boom
    allowed = _verify(quiet, quiet_token, {"agent_id": "shopper-01", "action": _action("act_allow")})
    assert allowed.content == (FIXTURES / "allow.bin").read_bytes()
    assert calls == []
    client = _client(hold_queue=True)
    token = _ready(client, agreements=2)
    client.app.state.bureau.repo.insert_hold = boom
    stepped = _verify(client, token, {"agent_id": "shopper-01", "action": _action("act_step")})
    assert stepped.json()["verdict"] == "STEP_UP"
    assert stepped.json()["verdict"] != "ALLOW"
    assert REASON_UNAVAILABLE in stepped.json()["reasons"]
    assert calls == ["insert"]
    forced = hold_unavailable_decision(
        {"verdict": "ALLOW", "kata_decision": "ALLOW", "reasons": [], "messages": ["kept"]}
    )
    assert forced["verdict"] == "STEP_UP"
    assert forced["kata_decision"] == "STEP_UP"
    assert forced["verdict"] != "ALLOW"
    assert forced["reasons"][0] == REASON_UNAVAILABLE

    from kata_service.hold_queue import HoldStoreError

    closed = _client(hold_queue=True, agent_authority=True)
    closed_token = _ready(closed)
    assert closed.post("/internal/agent-authority/shopper-01/level", headers=ADMIN, json={"level": 1}).status_code == 200
    created = _verify(closed, closed_token, {"agent_id": "shopper-01", "action": _action("act_closed", amount=10)}).json()
    assert _approve(closed, created["hold_id"]).status_code == 200

    def unread():
        raise HoldStoreError("store down")

    closed.app.state.bureau.repo.holds_supported = unread
    used = _use(closed, closed_token, _action("act_closed", amount=10), created["hold_id"])
    assert used.status_code == 200, used.text
    assert used.json()["verdict"] == "STEP_UP"
    assert used.json()["verdict"] != "ALLOW"
    assert REASON_UNAVAILABLE in used.json()["reasons"]


def test_missing_table_keeps_step_up_bytes_and_admin_is_not_available():
    client = _client(hold_queue=True)
    token = _ready(client, agreements=2)
    client.app.state.bureau.repo.holds_supported = lambda: False
    stepped = _verify(client, token, {"agent_id": "shopper-01", "action": _action("act_step")})
    assert stepped.content == (FIXTURES / "step_up.bin").read_bytes()
    assert b"HOLD_UNAVAILABLE" not in stepped.content
    assert b"hold_id" not in stepped.content
    assert stepped.json()["verdict"] == "STEP_UP"
    plain = _client(hold_queue=True)
    plain_token = _ready(plain)
    plain.app.state.bureau.repo.holds_supported = lambda: False
    allowed = _verify(plain, plain_token, {"agent_id": "shopper-01", "action": _action("act_allow")})
    assert allowed.content == (FIXTURES / "allow.bin").read_bytes()
    assert allowed.json()["verdict"] == "ALLOW"
    blocked = _client(hold_queue=True)
    blocked_token = _ready(blocked)
    blocked.app.state.bureau.repo.holds_supported = lambda: False
    denied = _verify(blocked, blocked_token, {"agent_id": "shopper-01", "action": _action("act_ceiling", amount=5000)})
    assert denied.content == (FIXTURES / "deny_ceiling.bin").read_bytes()
    assert denied.json()["verdict"] == "DENY"
    listed = client.get("/internal/holds", headers=ADMIN)
    assert listed.status_code == 503
    assert listed.json()["error"] == "not available"
    body = {"reviewer_id": REVIEWER, "reason": "because"}
    for path in (
        "/internal/holds/hold_missing/approve",
        "/internal/holds/hold_missing/reject",
    ):
        response = client.post(path, headers=ADMIN, json=body)
        assert response.status_code == 503
        assert response.json()["error"] == "not available"


def test_audit_chain_records_reviewer_on_approve_and_reject():
    client = _client(hold_queue=True, agent_authority=True, hold_ttl_seconds=60)
    token = _ready(client)
    assert client.post("/internal/agent-authority/shopper-01/level", headers=ADMIN, json={"level": 1}).status_code == 200
    first_action = _action("act_audit_a", amount=10)
    second_action = _action("act_audit_b", amount=10)
    third_action = _action("act_audit_c", amount=10)
    first = _verify(client, token, {"agent_id": "shopper-01", "action": first_action}).json()
    second = _verify(client, token, {"agent_id": "shopper-01", "action": second_action}).json()
    third = _verify(client, token, {"agent_id": "shopper-01", "action": third_action}).json()
    assert _approve(client, first["hold_id"], reviewer=REVIEWER).status_code == 200
    assert _reject(client, second["hold_id"], reviewer=OTHER_REVIEWER, reason="declined").status_code == 200
    assert _use(client, token, first_action, first["hold_id"]).json()["verdict"] == "ALLOW"
    audit_later = FROZEN + timedelta(seconds=61)
    client.app.state.bureau._now = lambda audit_later=audit_later: audit_later
    expired = _verify(client, token, {"agent_id": "shopper-01", "action": third_action})
    assert expired.json()["verdict"] == "DENY"
    assert expired.json()["reasons"] == [REASON_EXPIRED]
    repo = client.app.state.bureau.repo
    chain = repo.audit_chain()
    assert chain["ok"] is True, chain
    rows = repo.list_audit(None)
    by_event = {}
    for row in rows:
        path = row["path"]
        if "/internal/holds/" not in path:
            continue
        event = path.rsplit("/", 1)[-1]
        by_event.setdefault(event, []).append(row)
    assert len(by_event["created"]) == 3
    assert len(by_event["approved"]) == 1
    assert len(by_event["rejected"]) == 1
    assert len(by_event["expired"]) == 1
    approved = by_event["approved"][0]
    rejected = by_event["rejected"][0]
    assert approved["purpose_code"] == REVIEWER
    assert approved["key_id"] == REVIEWER
    assert rejected["purpose_code"] == OTHER_REVIEWER
    assert rejected["key_id"] == OTHER_REVIEWER
    assert audit_row_hash(approved["prev_hash"], approved) == approved["hash"]
    assert audit_row_hash(rejected["prev_hash"], rejected) == rejected["hash"]
    assert audit_row_hash(by_event["expired"][0]["prev_hash"], by_event["expired"][0]) == by_event["expired"][0]["hash"]
    assert repo.get_hold(first["hold_id"])["reviewer_id"] == REVIEWER
    assert repo.get_hold(second["hold_id"])["reviewer_id"] == OTHER_REVIEWER


def _cases():
    from test_decision_rationale import CASES

    return CASES


def _approve(client, hold_id: str, *, reviewer: str = REVIEWER, reason: str = "customer confirmed"):
    return client.post(
        f"/internal/holds/{hold_id}/approve",
        headers=ADMIN,
        json={"reviewer_id": reviewer, "reason": reason},
    )


def _reject(client, hold_id: str, *, reviewer: str = REVIEWER, reason: str = "declined"):
    return client.post(
        f"/internal/holds/{hold_id}/reject",
        headers=ADMIN,
        json={"reviewer_id": reviewer, "reason": reason},
    )


def _use(client, token: str, action: dict, hold_id: str):
    return client.post(
        "/v1/verify",
        headers=_auth(token),
        json={"agent_id": "shopper-01", "action": action, "hold_id": hold_id},
    )


def _approved_release(*, action_id: str = "act_release", amount: int = 10):
    client = _client(hold_queue=True, agent_authority=True)
    token = _ready(client)
    assert client.post("/internal/agent-authority/shopper-01/level", headers=ADMIN, json={"level": 1}).status_code == 200
    action = _action(action_id, amount=amount)
    created = _verify(client, token, {"agent_id": "shopper-01", "action": action}).json()
    assert created["verdict"] == "STEP_UP"
    assert created["reasons"] == ["AUTHORITY_STEP_UP"]
    approved = _approve(client, created["hold_id"])
    assert approved.status_code == 200, approved.text
    assert approved.json()["status"] == "approved"
    assert approved.json()["reviewer_id"] == REVIEWER
    return client, token, action, created["hold_id"]


def _assert_binding_rejected(client, token: str, hold_id: str, action: dict, kind: str) -> None:
    hold = client.app.state.bureau.repo.get_hold(hold_id)
    assert binding_failure(hold, {"agent_id": "shopper-01", "action": action}) == kind
    response = _use(client, token, action, hold_id)
    assert response.status_code == 409
    assert response.json()["error"] == "hold binding does not match"
    assert response.json().get("verdict") != "ALLOW"
    stored = client.app.state.bureau.repo.get_hold(hold_id)
    assert stored["status"] == "approved"
    assert stored["used_at"] is None
    assert stored["reviewer_id"] == REVIEWER
