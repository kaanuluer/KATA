# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: Apache-2.0
"""Decisions Kaan made on the open questions for the intent agreement."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from kata_intent import KataError, register_confirmation_renderer
from kata_intent.document import signing_document
from kata_intent.jws import sign_jws
from kata_intent.values import text_hash

from conftest import AT, activate, bound_eval, laptop_intent, propose, purchase

MANDATE_TYP = "kata-mandate+jws"


def _turkish(mandate):
    intent = mandate["intent"]
    agent = mandate["agent"]["agent_id"]
    return (
        f"K. Uluer, {agent} ajanına {intent['maximum_amount']} {intent['currency']} "
        "tavana kadar elektronik alışverişi için yetki verir."
    )


def test_confirmation_is_the_text_kata_produced(principal_key, agent_key):
    register_confirmation_renderer("tr", _turkish)
    agreement = propose(principal_key, agent_key, confirmation_language="tr")
    invented = "The wallet wrote a different Turkish sentence."
    with pytest.raises(KataError, match="confirmation text must be the text KATA produced"):
        agreement.accept(principal_key, AT, rendering_text=invented, confirmed_text=invented)
    text = agreement.rendering_preview()
    agreement.accept(principal_key, AT, rendering_text=text, confirmed_text=text)
    result = bound_eval(agreement, principal_key, agent_key)
    assert result.verdict == "ALLOW"
    assert agreement.mandate["rendering"]["text"] == text
    assert text.startswith("K. Uluer, shopper-01 ajanına 1500 CAD")

    forged = agreement.to_dict()
    mandate = forged["mandates"][0]
    mandate["rendering"] = {"hash": text_hash(invented), "text": invented}
    mandate["signature"] = sign_jws(signing_document(mandate), principal_key, typ=MANDATE_TYP)
    rejected = bound_eval(forged, principal_key, agent_key)
    assert "RENDERING_MISMATCH" in rejected.reasons


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

    selected = bound_eval(agreement, principal_key, agent_key, purchase(action_id="act_laptop", amount=1100))
    assert selected.verdict == "ALLOW"

    unselected = bound_eval(agreement, principal_key, agent_key, purchase(action_id="act_either", amount=200))
    assert unselected.verdict == "STEP_UP"
    assert unselected.reasons == ("INTENT_NOT_SELECTED",)

    none = bound_eval(agreement, principal_key, agent_key, purchase(action_id="act_none", amount=5000))
    assert none.verdict == "DENY"
    assert none.reasons == ("NO_MATCHING_INTENT",)

    allowed = bound_eval(
        agreement,
        principal_key,
        agent_key,
        purchase(action_id="act_case", amount=300, parameters={"intent_id": "int_case", "quantity": 1}),
    )
    assert allowed.verdict == "ALLOW"

    denied = bound_eval(
        agreement,
        principal_key,
        agent_key,
        purchase(action_id="act_over_case", amount=500, parameters={"intent_id": "int_case", "quantity": 1}),
    )
    assert "AMOUNT_ABOVE_INTENT_CEILING" in denied.reasons
    _validator().validate(json.loads(agreement.to_json()))


def test_a_narrower_asserted_intent_is_allowed(principal_key, agent_key):
    agreement = activate(principal_key, agent_key)
    narrower = bound_eval(
        agreement,
        principal_key,
        agent_key,
        purchase(parameters={"asserted_intent": {"allowed_actions": ["purchase"], "maximum_amount": 100}, "quantity": 1}),
    )
    assert narrower.verdict == "ALLOW"

    wider = bound_eval(
        agreement,
        principal_key,
        agent_key,
        purchase(
            action_id="act_wide",
            parameters={"asserted_intent": {"allowed_actions": ["purchase", "transfer"]}, "quantity": 1},
        ),
    )
    assert "ASSERTED_INTENT_MISMATCH" in wider.reasons


def test_the_agreement_lives_inside_the_delegation(principal_key, agent_key):
    agreement = activate(principal_key, agent_key)
    result = bound_eval(agreement.to_delegation(), principal_key, agent_key)
    assert result.verdict == "ALLOW"
    assert "intent_agreement" in agreement.to_delegation()


def test_kata_ledger_rejects_a_charge_past_the_total(principal_key, agent_key):
    agreement = activate(principal_key, agent_key)
    agreement.record_allowed(purchase(action_id="act_old", amount=1300))
    result = bound_eval(agreement, principal_key, agent_key, purchase(action_id="act_next", amount=300))
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
