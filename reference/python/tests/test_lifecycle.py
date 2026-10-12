# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import copy

from kata_intent import Actor, KataError
from kata_intent.agreement import verify_event_chain, verify_revocation

from conftest import AT, EXPIRY, activate, propose

import pytest


def test_preview_is_what_gets_signed(principal_key, agent_key):
    agreement = propose(principal_key, agent_key)
    preview = agreement.rendering_preview()
    assert "1500 CAD" in preview
    assert "shopper-01" in preview
    assert agent_key.public.fingerprint in preview
    assert "Merchants allowed: any." in preview
    agreement.accept(principal_key, AT, confirmed_text=preview)
    assert agreement.mandate["rendering"]["text"] == preview
    assert agreement.status == "active"


def test_stale_confirmation_is_rejected(principal_key, agent_key):
    agreement = propose(principal_key, agent_key)
    with pytest.raises(KataError, match="confirmed text"):
        agreement.accept(principal_key, AT, confirmed_text="You authorize anything.")
    assert agreement.status == "proposed"
    assert "signature" not in agreement.mandate


def test_clarify_then_accept(principal_key, agent_key):
    agreement = propose(principal_key, agent_key)
    agreement.update_draft(
        actor=Actor("principal", "usr_9182"),
        at="2026-10-04T13:57:00Z",
        intent={"merchant_constraints": ["techstore.example"]},
        note="Only this store.",
    )
    assert agreement.status == "clarifying"
    agreement.accept(principal_key, "2026-10-04T13:58:00Z", confirmed_text=agreement.rendering_preview())
    assert agreement.status == "active"
    assert agreement.mandate["intent"]["merchant_constraints"] == ["techstore.example"]
    assert [event["type"] for event in agreement.events] == ["proposed", "clarified", "accepted", "activated"]
    assert verify_event_chain(agreement.events)


def test_required_acknowledgement_holds_the_agreement(principal_key, agent_key, merchant_key):
    agreement = propose(principal_key, agent_key, required_acknowledgements=["merchant"])
    agreement.accept(principal_key, AT, confirmed_text=agreement.rendering_preview())
    assert agreement.status == "accepted"
    agreement.acknowledge(
        role="merchant",
        party_id="mer_techstore",
        private_key=merchant_key,
        at="2026-10-04T13:59:00Z",
    )
    assert agreement.status == "active"


def test_agent_cannot_acknowledge_with_another_key(principal_key, agent_key, merchant_key):
    agreement = activate(principal_key, agent_key)
    with pytest.raises(KataError, match="bound agent"):
        agreement.acknowledge(
            role="agent",
            party_id="shopper-01",
            private_key=merchant_key,
            at="2026-10-04T13:59:00Z",
        )


def test_amend_keeps_the_old_mandate(principal_key, agent_key):
    agreement = activate(principal_key, agent_key)
    old_hash = agreement.events[-1]["mandate_hash"]
    agreement.amend(
        principal_key,
        "2026-10-04T16:00:00Z",
        intent={"maximum_amount": 800},
        confirmed_text=None,
    )
    assert agreement.status == "active"
    assert agreement.mandate["version"] == 2
    assert agreement.mandate["supersedes"] == old_hash
    assert agreement.mandate["intent"]["maximum_amount"] == 800
    assert agreement._record["mandate_history"][0]["intent"]["maximum_amount"] == 1500
    assert verify_event_chain(agreement.events)


def test_revoke_and_expire(principal_key, agent_key):
    agreement = activate(principal_key, agent_key)
    revocation = agreement.revoke(principal_key, "2026-10-04T18:00:00Z", reason="changed my mind")
    assert agreement.status == "revoked"
    assert verify_revocation(revocation, principal_key.public)
    with pytest.raises(KataError, match="revoked"):
        agreement.revoke(principal_key, "2026-10-04T18:01:00Z")

    other = activate(principal_key, agent_key)
    with pytest.raises(KataError, match="not expired"):
        other.expire("2026-10-04T18:00:00Z")
    other.expire("2026-10-11T00:00:00Z")
    assert other.status == "expired"


def test_round_trip_preserves_the_signature(principal_key, agent_key):
    agreement = activate(principal_key, agent_key)
    restored = type(agreement).from_json(agreement.to_json())
    assert restored.status == "active"
    assert restored.mandate["signature"] == agreement.mandate["signature"]
    assert verify_event_chain(restored.events)


def test_event_edit_breaks_the_chain(principal_key, agent_key):
    agreement = activate(principal_key, agent_key)
    tampered = copy.deepcopy(agreement.events)
    tampered[0]["note"] = "rewritten"
    assert verify_event_chain(tampered) is False


def test_wrong_principal_cannot_revoke(principal_key, agent_key):
    agreement = activate(principal_key, agent_key)
    with pytest.raises(KataError, match="does not match"):
        agreement.revoke(agent_key, "2026-10-04T18:00:00Z")


def test_window_disagreement_is_rejected(principal_key, agent_key):
    from conftest import laptop_intent

    intent = laptop_intent()
    intent["time_limit"] = EXPIRY
    with pytest.raises(KataError, match="time_limit"):
        propose(principal_key, agent_key, expires_at="2026-10-09T00:00:00Z", intent=intent)
