# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Decision rationale. Synthetic agreements only. The flag defaults off.

The golden files are the POST /v1/verify bodies from main at b1e9b48, with
GAB_DECISION_RATIONALE unset. The clock is frozen so the decision does not
depend on the calendar day.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

from fastapi.testclient import TestClient
from kata_intent import Actor, Agreement, private_key_from_seed

from kata_service.asgi import create_app, ensure_bureau
from kata_service.bureau import BureauService, MemoryRepo
from kata_service.decision_rationale import (
    _DENY_MILLI,
    _STEP_MILLI,
    attach_rationale,
    confidence_for,
    confidence_milli,
)
from kata_service.evidence.attach import decision_ref
from kata_service.settings import Settings, settings_from_env
from kata_service.store import MemoryStore

AT = "2026-10-04T13:55:00Z"
EXPIRY = "2026-12-31T23:59:59Z"
FROZEN = datetime(2026, 11, 13, 12, 0, tzinfo=timezone.utc)
FIXTURES = Path(__file__).parent / "fixtures" / "verify_flag_off"


def _render(payload: dict) -> bytes:
    return json.dumps(payload, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")


def _settings(**overrides) -> Settings:
    base = dict(
        database_url=None,
        schema_url=None,
        log_signing_seed=hashlib.sha256(b"rationale-golden-log").digest(),
        push_notifier_jwk=None,
        append_token=None,
        published_keys=(),
        fx_source_url="https://fx.test",
        admin_token="admin-test-token",
        rate_limit_per_minute=1000,
        verify_rate_limit_per_minute=1000,
        report_daily_cap=5,
    )
    base.update(overrides)
    return Settings(**base)


def _keys():
    return (
        private_key_from_seed(hashlib.sha256(b"rationale-principal").digest()),
        private_key_from_seed(hashlib.sha256(b"rationale-agent").digest()),
    )


def _agreement(agreement_id: str = "agr_rationale", intent_id: str = "int_laptop"):
    principal, agent = _keys()
    agreement = Agreement.propose(
        agreement_id=agreement_id,
        principal={"display_name": "A Principal", "id": "prn_person", "type": "human"},
        agent={"agent_id": "shopper-01"},
        agent_public_key=agent.public,
        intent={
            "allowed_actions": ["purchase"],
            "currency": "CAD",
            "intent_id": intent_id,
            "maximum_amount": 1500,
            "purpose": "purchase",
            "time_limit": EXPIRY,
            "version": 1,
        },
        limits={"cumulative_maximum": 2000},
        parent_limits={"cumulative_maximum": 2000, "currency": "CAD", "maximum_amount": 1500},
        actor=Actor("agent", "shopper-01"),
        at=AT,
        expires_at=EXPIRY,
    )
    agreement.accept(principal, AT, confirmed_text=agreement.rendering_preview())
    return agreement


def _action(action_id: str, amount: int = 10, currency: str = "CAD") -> dict:
    return {
        "action_id": action_id,
        "action_type": "purchase",
        "amount": amount,
        "context": {"merchant": "techstore.example"},
        "currency": currency,
        "item": "Laptop",
        "parameters": {"merchant": "techstore.example", "quantity": 1},
        "proposed_at": AT,
    }


def _evidence(nonce: str, *, accept: bool) -> dict:
    return {
        "source": "synthetic",
        "issuer": "https://issuer.example",
        "subject": "agent-synthetic",
        "key_id": "kid-synthetic",
        "nonce": nonce,
        "claims": {"purpose": "purchase"},
        "accept": accept,
    }


def _client(**overrides) -> TestClient:
    app = create_app(_settings(**overrides), MemoryStore())
    ensure_bureau(app)
    app.state.bureau._now = lambda: FROZEN
    return TestClient(app)


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _ready(client: TestClient, *, agreements: int = 1, active: bool = True) -> str:
    org = client.post(
        "/v1/orgs",
        headers=_auth("admin-test-token"),
        json={"name": "Harbor Agents", "org_type": "agent_operator"},
    )
    assert org.status_code == 200, org.text
    key = client.post(
        f"/v1/orgs/{org.json()['org_id']}/keys",
        headers=_auth("admin-test-token"),
        json={"name": "primary"},
    )
    assert key.status_code == 200, key.text
    token = key.json()["token"]
    _principal, agent = _keys()
    registered = client.post(
        "/v1/agents",
        headers=_auth(token),
        json={
            "agent_id": "shopper-01",
            "principal_id": "prn_person",
            "public_key": agent.public.to_jwk(),
            "verification_level": "operator_verified",
        },
    )
    assert registered.status_code == 200, registered.text
    ids = [("agr_rationale", "int_laptop"), ("agr_other", "int_other")]
    for agreement_id, intent_id in ids[:agreements]:
        stored = client.post(
            "/v1/agents/shopper-01/intents",
            headers={**_auth(token), "Content-Type": "application/json"},
            content=_agreement(agreement_id, intent_id).to_json(),
        )
        assert stored.status_code == 200, stored.text
    if not active:
        status = client.post(
            "/v1/agents/shopper-01/status",
            headers=_auth(token),
            json={"status": "suspended"},
        )
        assert status.status_code == 200, status.text
    return token


def _verify(client: TestClient, token: str, body: dict):
    response = client.post("/v1/verify", headers=_auth(token), json=body)
    assert response.status_code == 200, response.text
    return response


CASES = (
    ("allow", {}, {"agent_id": "shopper-01", "action": _action("act_allow")}),
    ("deny_ceiling", {}, {"agent_id": "shopper-01", "action": _action("act_ceiling", amount=5000)}),
    ("deny_currency", {}, {"agent_id": "shopper-01", "action": _action("act_currency", currency="USD")}),
    ("deny_no_agreement", {"agreements": 0}, {"agent_id": "shopper-01", "action": _action("act_none")}),
    ("deny_inactive", {"active": False}, {"agent_id": "shopper-01", "action": _action("act_inactive")}),
    ("step_up", {"agreements": 2}, {"agent_id": "shopper-01", "action": _action("act_step")}),
)


def _case(name: str, ready: dict, body: dict, **flags):
    client = _client(**flags)
    token = _ready(client, **ready)
    return client, _verify(client, token, body)


def test_flag_defaults_off():
    assert settings_from_env({}).decision_rationale is False
    assert settings_from_env({"GAB_DECISION_RATIONALE": "0"}).decision_rationale is False
    assert settings_from_env({"GAB_DECISION_RATIONALE": "1"}).decision_rationale is True
    assert settings_from_env({"GAB_DECISION_RATIONALE": "yes"}).decision_rationale is True
    assert BureauService(MemoryRepo()).decision_rationale is False
    payload = {"verdict": "ALLOW", "kata_decision": "ALLOW", "reasons": []}
    assert attach_rationale(SimpleNamespace(decision_rationale=False), {}, payload) is payload


def test_flag_off_verify_matches_golden_bytes():
    assert _client().app.state.settings.decision_rationale is False
    for name, ready, body in CASES:
        _client_for_case, response = _case(name, ready, body)
        golden = (FIXTURES / f"{name}.bin").read_bytes()
        assert response.content == golden
        assert "rationale" not in response.json()
        assert _render(response.json()) == response.content
    ignored = {
        "agent_id": "shopper-01",
        "action": _action("act_allow"),
        "external_evidence": _evidence("nonce-golden", accept=False),
    }
    _client_for_case, response = _case("allow", {}, ignored)
    assert response.content == (FIXTURES / "allow.bin").read_bytes()


def test_confidence_is_a_fixed_function():
    assert confidence_milli("ALLOW", "ALLOW", [], 620, True, []) == 674
    assert confidence_for("ALLOW", "ALLOW", [], 620, True, []) == 674 / 1000
    assert confidence_milli("ALLOW", "ALLOW", [], 1000, False, []) == 950
    assert confidence_milli("ALLOW", "ALLOW", [], 1000, True, []) == 750
    ceiling = ["AMOUNT_ABOVE_INTENT_CEILING", "ACTION_EXCEEDS_INTENT", "CUMULATIVE_LIMIT_EXCEEDED"]
    assert confidence_milli("DENY", "BLOCK", ceiling, 620, True, []) == 930
    assert confidence_milli("DENY", "BLOCK", ["CURRENCY_MISMATCH"], 0, True, []) == 920
    assert confidence_milli("DENY", "BLOCK", ["NO_ACTIVE_AGREEMENT"], 0, True, []) == 950
    assert confidence_milli("DENY", "BLOCK", ["AGENT_NOT_ACTIVE"], 0, True, []) == 970
    assert confidence_milli("STEP_UP", "STEP_UP", ["AGREEMENT_NOT_SELECTED"], 0, True, []) == 580
    assert confidence_milli("DENY", "BLOCK", ["NOT_A_REAL_CODE"], 0, True, []) == 880
    assert confidence_milli("ALLOW", "ALLOW", [], 620, True, ["valid"]) == 704
    assert confidence_milli("ALLOW", "ALLOW", [], 620, True, ["invalid"]) == 634
    assert confidence_milli("ALLOW", "ALLOW", [], 620, True, ["unverifiable"]) == 659
    assert confidence_milli("DENY", "BLOCK", ["MANDATE_TAMPERED"], 0, False, ["valid"]) == 1000
    assert confidence_milli("ALLOW", "ALLOW", [], 0, True, ["invalid"]) == 510
    first = confidence_for("ALLOW", "ALLOW", [], 620, True, ["valid"])
    second = confidence_for("ALLOW", "ALLOW", [], 620, True, ["valid"])
    assert first == second
    assert 0 <= first <= 1
    for code in _DENY_MILLI:
        for results in ([], ["valid"], ["invalid"], ["unverifiable"], ["valid", "invalid"]):
            got = confidence_milli("DENY", "BLOCK", [code], 620, True, results)
            assert 0 <= got <= 1000
    for code in _STEP_MILLI:
        got = confidence_milli("STEP_UP", "STEP_UP", [code], 620, True, ["invalid"])
        assert 0 <= got <= 1000


def test_flag_on_adds_rationale_without_changing_the_decision():
    seen: list[float] = []
    for name, ready, body in CASES:
        client, response = _case(name, ready, body, decision_rationale=True)
        payload = response.json()
        rationale = payload["rationale"]
        assert rationale["reasons"] == payload["reasons"]
        assert isinstance(rationale["confidence"], float) or isinstance(rationale["confidence"], int)
        assert 0 <= rationale["confidence"] <= 1
        assert rationale["evidence"] == []
        agent = client.app.state.bureau.repo.get_agent("shopper-01")
        expected = confidence_for(
            payload["verdict"],
            payload["kata_decision"],
            payload["reasons"],
            int(agent["score"]),
            bool(agent["cold_start"]),
            [],
        )
        assert rationale["confidence"] == expected
        seen.append(rationale["confidence"])
        without = dict(payload)
        del without["rationale"]
        assert _render(without) == (FIXTURES / f"{name}.bin").read_bytes()
    assert len(set(seen)) > 1
    again, repeated = _case(*CASES[0], decision_rationale=True)
    assert repeated.json()["rationale"]["confidence"] == seen[0]
    del again


def test_evidence_refs_resolve_to_that_decision():
    client = _client(decision_rationale=True, evidence_verifier=True)
    token = _ready(client)
    first_body = {
        "agent_id": "shopper-01",
        "action": _action("act_valid"),
        "external_evidence": _evidence("nonce-valid", accept=True),
    }
    second_body = {
        "agent_id": "shopper-01",
        "action": _action("act_invalid"),
        "external_evidence": _evidence("nonce-invalid", accept=False),
    }
    plain_body = {"agent_id": "shopper-01", "action": _action("act_plain")}
    first = _verify(client, token, first_body).json()
    second = _verify(client, token, second_body).json()
    plain = _verify(client, token, plain_body).json()
    store = client.app.state.bureau._evidence_store
    assert plain["verdict"] == "ALLOW"
    assert plain["rationale"]["evidence"] == []
    assert plain["rationale"]["reasons"] == []
    _assert_refs(first, first_body, store)
    _assert_refs(second, second_body, store)
    first_ids = {item["evidence_id"] for item in first["rationale"]["evidence"]}
    second_ids = {item["evidence_id"] for item in second["rationale"]["evidence"]}
    assert first_ids.isdisjoint(second_ids)
    assert first["kata_decision"] == "ALLOW"
    assert second["kata_decision"] == "ALLOW"
    agent = client.app.state.bureau.repo.get_agent("shopper-01")
    score = int(agent["score"])
    cold = bool(agent["cold_start"])
    valid = confidence_milli("ALLOW", "ALLOW", [], score, cold, ["valid"])
    invalid = confidence_milli("ALLOW", "ALLOW", [], score, cold, ["invalid"])
    assert valid - invalid == 70
    assert first["rationale"]["confidence"] == valid / 1000
    assert second["rationale"]["confidence"] == invalid / 1000


def test_missing_evidence_does_not_fail_the_decision():
    ignored = {
        "agent_id": "shopper-01",
        "action": _action("act_allow"),
        "external_evidence": _evidence("nonce-ignored", accept=False),
    }
    _client_for_case, response = _case("allow", {}, ignored, decision_rationale=True)
    payload = response.json()
    assert payload["rationale"]["evidence"] == []
    assert payload["verdict"] == "ALLOW"
    without = dict(payload)
    del without["rationale"]
    assert _render(without) == (FIXTURES / "allow.bin").read_bytes()

    client = _client(decision_rationale=True, evidence_verifier=True)
    token = _ready(client)

    class Boom:
        def list_evidence(self, decision_ref=None):
            raise RuntimeError("evidence store unavailable")

        def save_evidence(self, record):
            raise RuntimeError("evidence store unavailable")

    client.app.state.bureau._evidence_store = Boom()
    broken = _verify(
        client,
        token,
        {
            "agent_id": "shopper-01",
            "action": _action("act_broken"),
            "external_evidence": {"source": "not-a-protocol"},
        },
    )
    body = broken.json()
    assert body["verdict"] == "ALLOW"
    assert body["kata_decision"] == "ALLOW"
    assert body["rationale"]["evidence"] == []
    assert 0 <= body["rationale"]["confidence"] <= 1
    assert body["rationale"]["reasons"] == body["reasons"]


def _assert_refs(payload: dict, body: dict, store) -> None:
    rationale = payload["rationale"]
    assert rationale["reasons"] == payload["reasons"]
    assert 0 <= rationale["confidence"] <= 1
    ref = decision_ref(body, payload)
    rows = [row for row in store.list_evidence(ref) if row["decision_ref"] == ref]
    assert rows
    assert [item["evidence_id"] for item in rationale["evidence"]] == [row["evidence_id"] for row in rows]
    for item, row in zip(rationale["evidence"], rows, strict=True):
        assert item["decision_ref"] == row["decision_ref"] == ref
        assert item["payload_hash"] == row["evidence"]["payload_hash"]
        assert item["evidence_id"] == row["evidence_id"]
    agent_rows = store.list_evidence()
    cited = {item["evidence_id"] for item in rationale["evidence"]}
    for row in agent_rows:
        if row["decision_ref"] != ref:
            assert row["evidence_id"] not in cited
