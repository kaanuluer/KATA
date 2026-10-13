# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: Apache-2.0
"""Shared fixtures for the intent-agreement reference tests."""

from __future__ import annotations

import hashlib

import pytest

from kata_intent import Actor, Agreement, private_key_from_seed

AT = "2026-10-04T13:55:00Z"
NOW = "2026-10-04T14:02:11Z"
EXPIRY = "2026-10-10T23:59:59Z"


def _key(label: str):
    return private_key_from_seed(hashlib.sha256(label.encode("utf-8")).digest())


@pytest.fixture
def principal_key():
    return _key("kata-test-principal")


@pytest.fixture
def agent_key():
    return _key("kata-test-agent")


@pytest.fixture
def merchant_key():
    return _key("kata-test-merchant")


def laptop_intent(**overrides):
    intent = {
        "allowed_actions": ["search", "compare", "purchase"],
        "category": "electronics",
        "constraints": {"max_items": 1},
        "currency": "CAD",
        "intent_id": "int_9f31",
        "maximum_amount": 1500,
        "merchant_constraints": [],
        "natural_language_source": "Find and buy a laptop for me, maximum CAD 1,500.",
        "purpose": "purchase",
        "time_limit": EXPIRY,
        "version": 1,
    }
    intent.update(overrides)
    return intent


def propose(principal_key, agent_key, **kwargs) -> Agreement:
    del principal_key
    params = {
        "agreement_id": "agr_laptop",
        "principal": {"display_name": "K. Uluer", "id": "usr_9182", "type": "human"},
        "agent": {"agent_id": "shopper-01"},
        "agent_public_key": agent_key.public,
        "intent": laptop_intent(),
        "actor": Actor("agent", "shopper-01"),
        "at": AT,
        "delegation_id": "dlg_77",
        "limits": {"cumulative_maximum": 1500, "frequency": {"max_count": 5, "per": "agreement"}},
        "not_before": AT,
        "expires_at": EXPIRY,
    }
    params.update(kwargs)
    return Agreement.propose(**params)


def activate(principal_key, agent_key, **kwargs) -> Agreement:
    agreement = propose(principal_key, agent_key, **kwargs)
    preview = agreement.rendering_preview()
    agreement.accept(principal_key, AT, confirmed_text=preview)
    return agreement


def purchase(**overrides):
    action = {
        "action_id": "act_1300",
        "action_type": "purchase",
        "amount": 1300,
        "context": {"merchant": "techstore.example"},
        "currency": "CAD",
        "item": "Laptop",
        "parameters": {"merchant": "techstore.example", "quantity": 1, "sku": "LAP-1300"},
        "proposed_at": NOW,
    }
    action.update(overrides)
    return action


def bound_eval(agreement, principal_key, agent_key, action=None, **kwargs):
    """Evaluate with the ledger head, sequence, and a fresh replica time.

    A cumulative or frequency limit denies when the check omits the head.
    ``NOW`` is several minutes after the agreement was created, so the
    replica time has to be passed explicitly or the check steps up as stale.
    """

    from kata_intent import evaluate

    explicit = set(kwargs)
    params = {
        "principal_public_key": principal_key.public,
        "agent_id": "shopper-01",
        "agent_public_key": agent_key.public,
        "now": NOW,
        "ledger_as_of": NOW,
    }
    params.update(kwargs)
    if "now" in explicit and "ledger_as_of" not in explicit:
        params["ledger_as_of"] = params["now"]
    holder = agreement
    if isinstance(agreement, dict) and isinstance(agreement.get("intent_agreement"), dict):
        holder = agreement["intent_agreement"]
    if "ledger_sequence" not in explicit:
        if "ledger" in explicit:
            ledger = params["ledger"]
            if ledger is not None:
                params["ledger_sequence"] = len(ledger)
                if "ledger_head" not in explicit:
                    last = ledger[-1] if ledger else None
                    params["ledger_head"] = last.get("entry_hash") if isinstance(last, dict) else None
        elif hasattr(holder, "ledger_sequence"):
            params["ledger_sequence"] = holder.ledger_sequence
            if "ledger_head" not in explicit:
                params["ledger_head"] = holder.ledger_head
        elif isinstance(holder, dict) and "ledger" in holder:
            params["ledger_sequence"] = int(holder.get("ledger_sequence") or len(holder.get("ledger") or []))
            if "ledger_head" not in explicit:
                params["ledger_head"] = holder.get("ledger_head")
    return evaluate(agreement, purchase() if action is None else action, **params)
