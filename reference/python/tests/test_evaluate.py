# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from kata_intent import Policy, evaluate
from kata_intent.agreement import seal_ledger
from kata_intent.fx import DailyTableRates

from conftest import AT, EXPIRY, NOW, activate, bound_eval, propose, purchase


def _eval(agreement, principal_key, agent_key, action=None, **kwargs):
    return bound_eval(agreement, principal_key, agent_key, action, **kwargs)


def test_in_scope_purchase_is_allowed(principal_key, agent_key):
    agreement = activate(principal_key, agent_key)
    result = _eval(agreement, principal_key, agent_key)
    assert result.verdict == "ALLOW"
    assert result.reasons == ()
    assert result.kata_decision == "ALLOW"
    assert result.required_action == "NONE"
    assert result.mandate_hash
    assert "1500 CAD" in agreement.mandate["rendering"]["text"]


def test_over_ceiling_is_denied(principal_key, agent_key):
    agreement = activate(principal_key, agent_key)
    delegation = {
        "agent": {"agent_id": "shopper-01"},
        "delegation_id": "dlg_77",
        "expires_at": EXPIRY,
        "principal": {"id": "usr_9182", "type": "human"},
        "scope": {
            "allowed_action_verbs": ["search", "compare", "purchase"],
            "currency": "CAD",
            "intent_ids": ["int_9f31"],
            "maximum_amount": 1500,
        },
        "status": "active",
    }
    result = _eval(
        agreement,
        principal_key,
        agent_key,
        purchase(action_id="act_5501", amount=4200, item="MacBook Pro 14-inch"),
        delegation=delegation,
    )
    assert result.verdict == "DENY"
    assert result.kata_decision == "BLOCK"
    assert "AMOUNT_ABOVE_INTENT_CEILING" in result.reasons
    assert "ACTION_EXCEEDS_INTENT" in result.reasons
    assert "DELEGATION_SCOPE_MISMATCH" in result.reasons
    assert result.required_action == "HUMAN_APPROVAL"


def test_wrong_merchant_and_category(principal_key, agent_key):
    agreement = activate(
        principal_key,
        agent_key,
        intent={
            "allowed_actions": ["purchase"],
            "category": "electronics",
            "currency": "CAD",
            "intent_id": "int_9f31",
            "maximum_amount": 1500,
            "merchant_constraints": ["techstore.example"],
            "purpose": "purchase",
            "time_limit": EXPIRY,
            "version": 1,
        },
    )
    merchant = _eval(
        agreement,
        principal_key,
        agent_key,
        purchase(context={"merchant": "other.example"}, parameters={"merchant": "other.example", "quantity": 1}),
    )
    assert merchant.verdict == "DENY"
    assert "MERCHANT_NOT_ALLOWED" in merchant.reasons

    category = _eval(
        agreement,
        principal_key,
        agent_key,
        purchase(parameters={"category": "travel", "merchant": "techstore.example", "quantity": 1}),
    )
    assert "CATEGORY_MISMATCH" in category.reasons


def test_currency_mismatch(principal_key, agent_key):
    result = _eval(activate(principal_key, agent_key), principal_key, agent_key, purchase(currency="USD"))
    assert result.verdict == "DENY"
    assert "CURRENCY_MISMATCH" in result.reasons


def test_expired_and_not_yet_valid(principal_key, agent_key):
    agreement = activate(principal_key, agent_key)
    expired = _eval(agreement, principal_key, agent_key, now="2026-10-11T00:00:00Z")
    assert expired.verdict == "DENY"
    assert "MANDATE_EXPIRED" in expired.reasons

    early = _eval(agreement, principal_key, agent_key, purchase(proposed_at="2026-10-04T13:00:00Z"), now=AT)
    assert "MANDATE_NOT_YET_VALID" in early.reasons


def test_revoked_mandate_and_external_log(principal_key, agent_key):
    agreement = activate(principal_key, agent_key)
    revocation = agreement.revoke(principal_key, "2026-10-04T18:00:00Z")
    denied = _eval(agreement, principal_key, agent_key, now="2026-10-04T18:30:00Z")
    assert denied.verdict == "DENY"
    assert "MANDATE_REVOKED" in denied.reasons

    other = activate(principal_key, agent_key, agreement_id="agr_other")
    # A revocation names one agreement and one mandate hash.
    untouched = _eval(other, principal_key, agent_key, extra_revocations=[revocation])
    assert untouched.verdict == "ALLOW"
    assert revocation["agreement_id"] != other.agreement_id


def test_stripped_revocation_needs_a_pinned_head_or_a_log(principal_key, agent_key):
    agreement = activate(principal_key, agent_key)
    before = agreement.to_json()
    head_before = agreement.log_head
    revocation = agreement.revoke(principal_key, "2026-10-04T18:00:00Z")
    restored = type(agreement).from_json(before)
    gap = _eval(restored, principal_key, agent_key)
    assert gap.verdict == "ALLOW"

    pinned = _eval(restored, principal_key, agent_key, expected_log_head=agreement.log_head)
    assert pinned.verdict == "DENY"
    assert "AGREEMENT_LOG_TAMPERED" in pinned.reasons

    logged = _eval(restored, principal_key, agent_key, extra_revocations=[revocation])
    assert logged.verdict == "DENY"
    assert "MANDATE_REVOKED" in logged.reasons
    assert head_before != agreement.log_head


def test_tampered_amount_fails_verification(principal_key, agent_key):
    agreement = activate(principal_key, agent_key)
    record = agreement.to_dict()
    record["mandates"][0]["intent"]["maximum_amount"] = 9000
    result = _eval(record, principal_key, agent_key)
    assert result.verdict == "DENY"
    assert result.reasons == ("MANDATE_TAMPERED",)


def test_wrong_principal_key_is_rejected(principal_key, agent_key):
    agreement = activate(principal_key, agent_key)
    result = _eval(agreement, agent_key, agent_key)
    assert result.verdict == "DENY"
    assert result.reasons == ("PRINCIPAL_KEY_MISMATCH",)


def test_unbound_principal_key_steps_up(principal_key, agent_key):
    agreement = activate(principal_key, agent_key)
    result = evaluate(
        agreement,
        purchase(),
        agent_id="shopper-01",
        ledger=[],
        ledger_sequence=0,
        ledger_head=None,
        ledger_as_of=NOW,
        now=NOW,
    )
    assert result.verdict == "STEP_UP"
    assert "PRINCIPAL_KEY_UNBOUND" in result.reasons


def test_cumulative_and_frequency(principal_key, agent_key):
    agreement = activate(principal_key, agent_key)
    record = agreement.to_dict()
    del record["ledger"]
    missing = _eval(record, principal_key, agent_key, ledger=None)
    assert missing.verdict == "DENY"
    assert "CUMULATIVE_STATE_UNAVAILABLE" in missing.reasons
    assert "FREQUENCY_STATE_UNAVAILABLE" in missing.reasons

    prior = seal_ledger(
        [
            {
                "action_id": "act_old",
                "amount": 1300,
                "at": "2026-10-04T14:00:00Z",
                "currency": "CAD",
                "outcome": "settled",
            }
        ]
    )
    over = _eval(agreement, principal_key, agent_key, ledger=prior)
    assert over.verdict == "DENY"
    assert "CUMULATIVE_LIMIT_EXCEEDED" in over.reasons

    frequent = activate(
        principal_key,
        agent_key,
        agreement_id="agr_freq",
        limits={"frequency": {"max_count": 1, "per": "P1D"}},
    )
    blocked = _eval(frequent, principal_key, agent_key, ledger=prior)
    assert "FREQUENCY_LIMIT_EXCEEDED" in blocked.reasons

    failed = seal_ledger(
        [
            {
                "action_id": "act_fail",
                "amount": 1300,
                "at": "2026-10-04T14:00:00Z",
                "currency": "CAD",
                "idempotency_key": "idem_failed",
                "outcome": "failed",
            }
        ]
    )
    honest = _eval(
        agreement,
        principal_key,
        agent_key,
        purchase(
            action_id="act_retry",
            settlement={"attempt": 2, "idempotency_key": "idem_new", "prior_attempt_status": "failed"},
        ),
        ledger=failed,
    )
    assert honest.verdict == "ALLOW"


def test_replay_and_retry_farming(principal_key, agent_key):
    agreement = activate(principal_key, agent_key)
    replay = _eval(agreement, principal_key, agent_key, seen_action_ids={"act_1300"})
    assert "ACTION_REPLAY" in replay.reasons

    farmed = _eval(
        agreement,
        principal_key,
        agent_key,
        purchase(
            action_id="act_again",
            settlement={"idempotency_key": "idem_new", "prior_attempt_status": "settled", "prior_idempotency_key": "idem_old"},
        ),
    )
    assert farmed.verdict == "DENY"
    assert "RETRY_FARMING" in farmed.reasons
    assert farmed.required_action == "NONE"


def test_asserted_intent_and_agent_binding(principal_key, agent_key):
    agreement = activate(principal_key, agent_key)
    asserted = _eval(
        agreement,
        principal_key,
        agent_key,
        purchase(parameters={"asserted_intent": {"maximum_amount": 5000}, "quantity": 1}),
    )
    assert "ASSERTED_INTENT_MISMATCH" in asserted.reasons

    bound = _eval(agreement, principal_key, agent_key, agent_id="other-agent")
    assert "AGENT_BINDING_MISMATCH" in bound.reasons


def test_price_and_fees(principal_key, agent_key):
    intent = {
        "allowed_actions": ["purchase"],
        "category": "electronics",
        "currency": "CAD",
        "fee_policy": {"allow_undisclosed": False, "allowed_codes": ["tax", "shipping"]},
        "intent_id": "int_9f32",
        "maximum_amount": 1500,
        "merchant_constraints": [],
        "price_expectation": {"currency": "CAD", "listed_price": 1000, "quoted_price": 1000, "tolerance_ratio": 1.15},
        "purpose": "purchase",
        "time_limit": EXPIRY,
        "version": 1,
    }
    agreement = activate(principal_key, agent_key, agreement_id="agr_price", intent=intent, limits={"cumulative_maximum": 1500})
    over = _eval(
        agreement,
        principal_key,
        agent_key,
        purchase(
            amount=1300,
            price={
                "charged_amount": 1300,
                "currency": "CAD",
                "fee_breakdown": [
                    {"amount": 1000, "code": "item", "disclosed": True},
                    {"amount": 300, "code": "service_fee", "disclosed": False},
                ],
                "listed_price": 1000,
                "quoted_price": 1000,
            },
        ),
    )
    assert over.verdict == "DENY"
    assert "CHARGE_EXCEEDS_QUOTE" in over.reasons
    assert "CHARGE_EXCEEDS_LISTED" in over.reasons
    assert "UNDISCLOSED_FEE" in over.reasons
    assert "FEE_NOT_ACCEPTED" in over.reasons

    inside = _eval(
        agreement,
        principal_key,
        agent_key,
        purchase(action_id="act_ok", amount=1100, price={"charged_amount": 1100, "listed_price": 1000, "quoted_price": 1000}),
    )
    assert inside.verdict == "ALLOW"


def test_over_broad_intent_steps_up(principal_key, agent_key):
    agreement = activate(
        principal_key,
        agent_key,
        agreement_id="agr_wide",
        expires_at=None,
        intent={
            "allowed_actions": ["purchase"],
            "currency": "CAD",
            "intent_id": "int_wide",
            "maximum_amount": 1500,
            "purpose": "purchase",
            "version": 1,
        },
    )
    result = _eval(agreement, principal_key, agent_key)
    assert result.verdict == "STEP_UP"
    assert "OVER_BROAD_INTENT" in result.reasons
    assert result.required_action == "HUMAN_APPROVAL"


def test_amended_hash_is_the_one_that_applies(principal_key, agent_key):
    agreement = activate(principal_key, agent_key)
    old = agreement.events[-1]["mandate_hash"]
    agreement.amend(principal_key, "2026-10-04T16:00:00Z", intent={"maximum_amount": 800})
    old_action = _eval(
        agreement,
        principal_key,
        agent_key,
        purchase(parameters={"mandate_hash": old, "quantity": 1}),
        now="2026-10-04T16:05:00Z",
    )
    assert "MANDATE_SUPERSEDED" in old_action.reasons
    under = _eval(agreement, principal_key, agent_key, purchase(amount=700), now="2026-10-04T16:05:00Z")
    assert under.verdict == "ALLOW"
    over = _eval(agreement, principal_key, agent_key, purchase(action_id="act_900", amount=900), now="2026-10-04T16:05:00Z")
    assert "AMOUNT_ABOVE_INTENT_CEILING" in over.reasons


def test_revocation_endpoint_steps_up_until_checked(principal_key, agent_key):
    agreement = activate(
        principal_key,
        agent_key,
        revocation_endpoint="https://example.test/kata/revocations/agr_laptop",
    )
    pending = _eval(agreement, principal_key, agent_key)
    assert pending.verdict == "STEP_UP"
    assert "REVOCATION_ENDPOINT_UNCHECKED" in pending.reasons
    checked = _eval(agreement, principal_key, agent_key, revocation_checked=True)
    assert checked.verdict == "ALLOW"


def test_missing_counterparty_ack_steps_up(principal_key, agent_key, merchant_key):
    agreement = propose(principal_key, agent_key, required_acknowledgements=["issuer"])
    agreement.accept(principal_key, AT, confirmed_text=agreement.rendering_preview())
    result = _eval(agreement, principal_key, agent_key)
    assert result.verdict == "STEP_UP"
    assert "COUNTERPARTY_ACK_REQUIRED" in result.reasons
    agreement.acknowledge(role="issuer", party_id="iss_1", private_key=merchant_key, at="2026-10-04T13:59:00Z")
    allowed = _eval(agreement, principal_key, agent_key)
    assert allowed.verdict == "ALLOW"


def test_unsigned_agreement_is_not_active(principal_key, agent_key):
    agreement = propose(principal_key, agent_key)
    result = _eval(agreement, principal_key, agent_key)
    assert result.verdict == "DENY"
    assert result.reasons == ("MANDATE_NOT_ACTIVE",)


def test_future_action_time_is_denied(principal_key, agent_key):
    later = (datetime(2026, 10, 4, 14, 2, 11, tzinfo=timezone.utc) + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    result = _eval(activate(principal_key, agent_key), principal_key, agent_key, purchase(proposed_at=later))
    assert "ACTION_TIME_IN_FUTURE" in result.reasons


def test_quantity_constraint(principal_key, agent_key):
    result = _eval(
        activate(principal_key, agent_key),
        principal_key,
        agent_key,
        purchase(parameters={"quantity": 3, "merchant": "techstore.example"}),
    )
    assert "CONSTRAINT_VIOLATED" in result.reasons


def test_delegation_revoked(principal_key, agent_key):
    result = _eval(
        activate(principal_key, agent_key),
        principal_key,
        agent_key,
        delegation={"status": "revoked", "scope": {"intent_ids": ["int_9f31"]}},
    )
    assert "DELEGATION_NOT_ACTIVE" in result.reasons


def test_settlement_mismatch_denies_without_revoking(principal_key, agent_key):
    agreement = activate(principal_key, agent_key)
    result = _eval(
        agreement,
        principal_key,
        agent_key,
        purchase(
            counterparty={
                "merchant_id": "mer_techstore",
                "registered_settlement_address": "payee_registered",
                "settlement_address": "payee_other",
            }
        ),
    )
    assert result.verdict == "DENY"
    assert "SETTLEMENT_ADDRESS_MISMATCH" in result.reasons
    assert agreement.status == "active"


def test_policy_can_flag_an_unscoped_ceiling(principal_key, agent_key):
    agreement = activate(
        principal_key,
        agent_key,
        agreement_id="agr_unscoped",
        intent={
            "allowed_actions": ["purchase"],
            "currency": "CAD",
            "intent_id": "int_open",
            "maximum_amount": 50000,
            "merchant_constraints": [],
            "purpose": "purchase",
            "time_limit": EXPIRY,
            "version": 1,
        },
    )
    result = _eval(
        agreement,
        principal_key,
        agent_key,
        policy=Policy(
            unscoped_amount_ceiling=10000,
            fx_rates=DailyTableRates({("CAD", "USD", "2026-10-04"): "0.75"}),
        ),
    )
    assert result.verdict == "STEP_UP"
    assert "OVER_BROAD_INTENT" in result.reasons
