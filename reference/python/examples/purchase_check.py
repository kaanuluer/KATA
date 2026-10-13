# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: Apache-2.0
"""A shopping agent tries one purchase inside the signed intent, then one outside it.

The seeds below are public demo material. They are not a principal's key.

Run from ``reference/python``:

    PYTHONPATH=src python3 examples/purchase_check.py
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from kata_intent import Actor, Agreement, evaluate, private_key_from_seed

EXPIRY = "2026-10-10T23:59:59Z"
NOW = "2026-10-04T14:02:11Z"


def main() -> int:
    principal = private_key_from_seed(hashlib.sha256(b"kata-demo-principal").digest())
    agent = private_key_from_seed(hashlib.sha256(b"kata-demo-agent").digest())
    agreement = Agreement.propose(
        agreement_id="agr_laptop",
        principal={"display_name": "K. Uluer", "id": "usr_9182", "type": "human"},
        agent={"agent_id": "shopper-01"},
        agent_public_key=agent.public,
        delegation_id="dlg_77",
        intent={
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
        },
        limits={"cumulative_maximum": 5000},
        not_before="2026-10-04T13:55:00Z",
        expires_at=EXPIRY,
        actor=Actor("agent", "shopper-01"),
        at="2026-10-04T13:55:00Z",
        note="Draft from the instruction.",
    )
    preview = agreement.rendering_preview()
    print("Principal reviews this before signing:")
    print(preview)
    print()
    agreement.accept(principal, "2026-10-04T13:56:00Z", confirmed_text=preview)
    print(f"Agreement {agreement.agreement_id} is {agreement.status}.")
    print()

    within = _purchase("act_1300", 1300, "Laptop")
    outside = _purchase("act_5501", 4200, "MacBook Pro 14-inch")
    within_result = _check(agreement, principal, agent, within)
    outside_result = _check(agreement, principal, agent, outside)
    print(_line("In scope", within, within_result))
    print(_line("Out of scope", outside, outside_result))

    agreement.revoke(principal, "2026-10-04T18:00:00Z", reason="changed my mind")
    after = _check(agreement, principal, agent, within, now="2026-10-04T18:30:00Z")
    print(_line("After revocation", within, after))

    ok = (
        within_result.verdict == "ALLOW"
        and outside_result.verdict == "DENY"
        and "AMOUNT_ABOVE_INTENT_CEILING" in outside_result.reasons
        and after.verdict == "DENY"
        and "MANDATE_REVOKED" in after.reasons
    )
    return 0 if ok else 1


def _purchase(action_id: str, amount: int, item: str) -> dict:
    return {
        "action_id": action_id,
        "action_type": "purchase",
        "amount": amount,
        "context": {"merchant": "techstore.example"},
        "currency": "CAD",
        "item": item,
        "parameters": {"merchant": "techstore.example", "quantity": 1},
        "proposed_at": NOW,
    }


def _check(agreement, principal, agent, action, now=NOW):
    # This process holds the ledger, so the check carries its head and a fresh replica time.
    return evaluate(
        agreement,
        action,
        principal_public_key=principal.public,
        agent_id="shopper-01",
        agent_public_key=agent.public,
        now=now,
        ledger_sequence=agreement.ledger_sequence,
        ledger_head=agreement.ledger_head,
        ledger_as_of=now,
    )


def _line(label: str, action: dict, result) -> str:
    reasons = ", ".join(result.reasons) if result.reasons else "none"
    return (
        f"{label}: {action['item']} at {action['amount']} {action['currency']}"
        f" -> {result.verdict} (KATA {result.kata_decision}; reasons: {reasons})"
    )


if __name__ == "__main__":
    sys.exit(main())
