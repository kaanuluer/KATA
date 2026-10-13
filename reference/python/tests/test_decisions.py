# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: Apache-2.0
"""Decisions Kaan made on the open questions for the intent agreement."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from kata_intent import KataError, evaluate

from conftest import AT, NOW, activate, laptop_intent, propose, purchase


def test_confirmation_may_be_any_language(principal_key, agent_key):
    agreement = propose(principal_key, agent_key)
    text = "K. Uluer, shopper-01 ajanına CAD 1500 tavana kadar elektronik alışverişi için yetki verir."
    agreement.accept(principal_key, AT, rendering_text=text, confirmed_text=text)
    result = evaluate(
        agreement,
        purchase(),
        principal_public_key=principal_key.public,
        agent_id="shopper-01",
        agent_public_key=agent_key.public,
        now=NOW,
    )
    assert result.verdict == "ALLOW"
    assert agreement.mandate["rendering"]["text"] == text


def test_several_intents_stay_inside_the_parent_set(principal_key, agent_key):
    agreement = activate(
        principal_key,
        agent_key,
        agreement_id="agr_multi",
        parent_limits={"cumulative_maximum": 2000, "currency": "CAD", "maximum_amount": 1500},
        limits={"cumulative_maximum": 1200, "frequency": {"max_count": 5, "per": "agreement"}},
    )
    agreement.add_intent(
        principal_key,
        AT,
        intent=laptop_intent(
            intent_id="int_case",
            maximum_amount=400,
            natural_language_source="Buy a laptop case.",
        ),
        limits={"cumulative_maximum": 800},
    )
    with pytest.raises(KataError, match="maximum_amount exceeds the parent set"):
        agreement.add_intent(
            principal_key,
            AT,
            intent=laptop_intent(intent_id="int_wide", maximum_amount=1600, natural_language_source="Too much."),
            limits={"cumulative_maximum": 100},
        )
    with pytest.raises(KataError, match="sum of intent cumulative slices"):
        agreement.add_intent(
            principal_key,
            AT,
            intent=laptop_intent(intent_id="int_sum", maximum_amount=100, natural_language_source="Another slice."),
            limits={"cumulative_maximum": 900},
        )

    unselected = evaluate(
        agreement,
        purchase(),
        principal_public_key=principal_key.public,
        agent_id="shopper-01",
        agent_public_key=agent_key.public,
        now=NOW,
    )
    assert unselected.verdict == "STEP_UP"
    assert unselected.reasons == ("INTENT_NOT_SELECTED",)

    allowed = evaluate(
        agreement,
        purchase(action_id="act_case", amount=300, parameters={"intent_id": "int_case", "quantity": 1}),
        principal_public_key=principal_key.public,
        agent_id="shopper-01",
        agent_public_key=agent_key.public,
        now=NOW,
    )
    assert allowed.verdict == "ALLOW"

    denied = evaluate(
        agreement,
        purchase(action_id="act_over_case", amount=500, parameters={"intent_id": "int_case", "quantity": 1}),
        principal_public_key=principal_key.public,
        agent_id="shopper-01",
        agent_public_key=agent_key.public,
        now=NOW,
    )
    assert "AMOUNT_ABOVE_INTENT_CEILING" in denied.reasons
    _validator().validate(json.loads(agreement.to_json()))


def test_a_narrower_asserted_intent_is_allowed(principal_key, agent_key):
    agreement = activate(principal_key, agent_key)
    narrower = evaluate(
        agreement,
        purchase(parameters={"asserted_intent": {"allowed_actions": ["purchase"], "maximum_amount": 100}, "quantity": 1}),
        principal_public_key=principal_key.public,
        agent_id="shopper-01",
        agent_public_key=agent_key.public,
        now=NOW,
    )
    assert narrower.verdict == "ALLOW"

    wider = evaluate(
        agreement,
        purchase(
            action_id="act_wide",
            parameters={"asserted_intent": {"allowed_actions": ["purchase", "transfer"]}, "quantity": 1},
        ),
        principal_public_key=principal_key.public,
        agent_id="shopper-01",
        agent_public_key=agent_key.public,
        now=NOW,
    )
    assert "ASSERTED_INTENT_MISMATCH" in wider.reasons


def test_the_agreement_lives_inside_the_delegation(principal_key, agent_key):
    agreement = activate(principal_key, agent_key)
    result = evaluate(
        agreement.to_delegation(),
        purchase(),
        principal_public_key=principal_key.public,
        agent_id="shopper-01",
        agent_public_key=agent_key.public,
        now=NOW,
    )
    assert result.verdict == "ALLOW"
    assert "intent_agreement" in agreement.to_delegation()


def test_kata_ledger_rejects_a_charge_past_the_total(principal_key, agent_key):
    agreement = activate(principal_key, agent_key)
    agreement.record_allowed(purchase(action_id="act_old", amount=1300))
    result = evaluate(
        agreement,
        purchase(action_id="act_next", amount=300),
        principal_public_key=principal_key.public,
        agent_id="shopper-01",
        agent_public_key=agent_key.public,
        now=NOW,
    )
    assert result.verdict == "DENY"
    assert "CUMULATIVE_LIMIT_EXCEEDED" in result.reasons


def _validator() -> Draft202012Validator:
    root = Path(__file__).resolve().parents[3] / "schemas"
    resources = []
    for name in ("intent.json", "intent-mandate.json", "agreement.json"):
        contents = json.loads((root / name).read_text())
        resources.append((contents["$id"], Resource.from_contents(contents)))
    schema = json.loads((root / "agreement.json").read_text())
    return Draft202012Validator(schema, registry=Registry().with_resources(resources))
