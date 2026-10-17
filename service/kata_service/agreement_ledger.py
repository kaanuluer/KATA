# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Spend history for a stored agreement.

ALLOW used to append every charge to the agreement document. The document now
keeps the sequence counter, the chain head, and a spend summary. Each charge
is a row in gab_agreement_allows. Evaluation reads the summary, not the row
history, so the stored document stays under AGREEMENT_DOCUMENT_MAX_BYTES.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from kata_intent.agreement import Agreement, seal_ledger, seal_ledger_entry
from kata_intent.canonical import canonical_bytes
from kata_intent.errors import KataError
from kata_intent.values import as_time, coerce, money, parse_time, require_text

AGREEMENT_DOCUMENT_MAX_BYTES = 65536
_COUNTING = frozenset({"allowed", "authorized", "settled"})
_SUMMARY_AT = "1970-01-01T00:00:00Z"


def document_octets(document: dict[str, Any]) -> int:
    return len(canonical_bytes(document))


def assert_document_bounded(document: dict[str, Any]) -> None:
    size = document_octets(document)
    if size > AGREEMENT_DOCUMENT_MAX_BYTES:
        raise KataError("agreement document exceeds the size bound")


def take_embedded_ledger(document: dict[str, Any]) -> list[dict[str, Any]]:
    """Pull a document-embedded ledger out, leaving the counter and a summary.

    An empty ledger is left untouched. A non-empty ledger is replaced with []
    and spend_summary is rebuilt from those entries.
    """

    ledger = document.get("ledger") or []
    if not isinstance(ledger, list) or not ledger:
        return []
    summary: dict[str, Any] = {}
    kept: list[dict[str, Any]] = []
    for entry in ledger:
        if not isinstance(entry, dict):
            continue
        kept.append(dict(entry))
        add_spend(summary, entry)
    document["spend_summary"] = summary
    document["ledger"] = []
    document["ledger_sequence"] = len(kept)
    last = kept[-1] if kept else None
    if last and last.get("entry_hash"):
        document["ledger_head"] = last["entry_hash"]
    if last and last.get("at"):
        document["ledger_as_of"] = last["at"]
    return kept


def add_spend(summary: dict[str, Any], entry: dict[str, Any]) -> None:
    if entry.get("outcome") not in _COUNTING or entry.get("amount") is None:
        return
    currency = str(entry.get("currency") or "")
    if not currency:
        return
    intent_id = str(entry.get("intent_id") or "")
    bucket = summary.get(currency)
    if not isinstance(bucket, dict):
        bucket = {}
        summary[currency] = bucket
    bucket[intent_id] = money(bucket.get(intent_id) or 0) + money(entry["amount"])


def summary_ledger(document: dict[str, Any]) -> tuple[list[dict[str, Any]], int, str | None]:
    """A short projection of spend_summary that the evaluator can sum.

    One sealed entry per currency and intent. This is not the stored history.
    """

    summary = document.get("spend_summary") or {}
    if not isinstance(summary, dict):
        return [], 0, None
    bodies: list[dict[str, Any]] = []
    for currency in sorted(summary):
        bucket = summary[currency]
        if not isinstance(bucket, dict):
            continue
        for intent_id in sorted(bucket):
            amount = money(bucket[intent_id] or 0)
            if amount == 0:
                continue
            bodies.append(
                {
                    "action_id": f"summary:{currency}:{intent_id}",
                    "amount": amount,
                    "at": _SUMMARY_AT,
                    "currency": str(currency),
                    "intent_id": str(intent_id),
                    "outcome": "allowed",
                }
            )
    if not bodies:
        return [], 0, None
    sealed = seal_ledger(bodies)
    return sealed, len(sealed), sealed[-1]["entry_hash"]


def append_allow(
    document: dict[str, Any],
    agreement: Agreement,
    action: dict[str, Any],
    *,
    at: str,
    intent_id: str | None,
) -> dict[str, Any]:
    """Record one ALLOW on the summary and return the sealed side-table entry.

    The document ledger stays empty. Sequence continues from ledger_sequence,
    and the new entry names the previous ledger_head.
    """

    if "ledger" not in document:
        raise KataError("agreement has no spend ledger")
    action = coerce(action)
    chosen = _chosen_intent(agreement, action, intent_id)
    entry: dict[str, Any] = {
        "action_id": require_text(action.get("action_id"), "action_id"),
        "at": as_time(at or action.get("proposed_at")),
        "currency": require_text(action.get("currency"), "currency"),
        "intent_id": chosen,
        "outcome": "allowed",
    }
    if action.get("amount") is not None:
        entry["amount"] = money(action["amount"])
    idempotency = (action.get("settlement") or {}).get("idempotency_key")
    if idempotency:
        entry["idempotency_key"] = idempotency
    sequence = int(document.get("ledger_sequence") or 0) + 1
    entry["sequence"] = sequence
    if sequence > 1:
        previous = document.get("ledger_head")
        if not previous:
            raise KataError("agreement ledger head is missing")
        entry["prev_entry_hash"] = previous
    sealed = seal_ledger_entry(entry)
    document["ledger"] = []
    document["ledger_sequence"] = sequence
    document["ledger_head"] = sealed["entry_hash"]
    document["ledger_as_of"] = sealed["at"]
    summary = document.get("spend_summary")
    if not isinstance(summary, dict):
        summary = {}
        document["spend_summary"] = summary
    add_spend(summary, sealed)
    return sealed


def selected_frequency(
    agreement: Agreement, action: dict[str, Any], intent_id: str | None
) -> tuple[str, dict[str, Any]] | None:
    chosen = _chosen_intent(agreement, action, intent_id)
    mandate = next(item for item in agreement.mandates if item["intent"]["intent_id"] == chosen)
    frequency = (mandate.get("limits") or {}).get("frequency")
    if not isinstance(frequency, dict):
        return None
    return chosen, frequency


def frequency_window_start(proposed_at: str, per: str | None) -> str | None:
    if per in (None, "agreement"):
        return None
    days = {"P1D": 1, "P7D": 7, "P1M": 30}.get(str(per))
    if days is None:
        return None
    return as_time(parse_time(proposed_at) - timedelta(days=days))


def _chosen_intent(agreement: Agreement, action: dict[str, Any], intent_id: str | None) -> str:
    chosen = intent_id or (action.get("parameters") or {}).get("intent_id")
    mandates = agreement.mandates
    if not chosen:
        if len(mandates) != 1:
            raise KataError("intent_id is required when several intents are live")
        return mandates[0]["intent"]["intent_id"]
    if not any(item["intent"]["intent_id"] == chosen for item in mandates):
        raise KataError(f"no live intent {chosen}")
    return str(chosen)
