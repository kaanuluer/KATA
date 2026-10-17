# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Breach register helpers.

Records store types of data, a count, and a hash. They do not store a copy of
the data. Retention on the row is 5 years from detected_at. This is an
engineering default recorded by the operator, not a legal determination or a
certification.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta
from typing import Any

from kata_intent.values import hash_document

BREACH_RETENTION_YEARS = 5
DATA_TYPES = frozenset(
    {
        "email",
        "phone",
        "name",
        "postal_address",
        "device_identifier",
        "credential",
        "payment_reference",
        "network_signal",
        "account_identifier",
    }
)
_HASH = re.compile(r"^(sha256:)?[0-9a-f]{64}$")
_STAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


class BreachInputError(ValueError):
    """The incident record is not types, a count, and a hash."""


def normalize_types(value: Any) -> list[str]:
    if not isinstance(value, list) or not value:
        raise BreachInputError("data_types must list one or more type labels")
    labels = []
    for item in value:
        text = str(item).strip().lower()
        if text not in DATA_TYPES:
            raise BreachInputError("data_types must be type labels")
        if text not in labels:
            labels.append(text)
    return labels


def normalize_note_hash(value: Any) -> str:
    if value in (None, ""):
        return ""
    text = str(value).strip().lower()
    if not _HASH.match(text):
        raise BreachInputError("note_hash must be a sha256 digest")
    return text


def expired_session_stamp(at: str) -> str:
    """A timestamp strictly before `at`, so a session check using `<` treats it as expired."""

    if not _STAMP.match(at):
        raise BreachInputError("at must be a UTC timestamp")
    parsed = datetime.strptime(at, "%Y-%m-%dT%H:%M:%SZ")
    return (parsed - timedelta(seconds=1)).strftime("%Y-%m-%dT%H:%M:%SZ")


def retain_until(detected_at: str) -> str:
    if not _STAMP.match(detected_at):
        raise BreachInputError("detected_at must be a UTC timestamp")
    day = datetime.strptime(detected_at[:10], "%Y-%m-%d")
    try:
        later = day.replace(year=day.year + BREACH_RETENTION_YEARS)
    except ValueError:
        later = day.replace(year=day.year + BREACH_RETENTION_YEARS, day=28)
    return later.strftime("%Y-%m-%d") + detected_at[10:]


def seal_breach(prev_hash: str | None, fields: dict[str, Any]) -> dict[str, Any]:
    labels = normalize_types(fields["data_types"])
    detected_at = str(fields["detected_at"])
    scope = fields.get("scope_count")
    if scope is not None and (not isinstance(scope, int) or isinstance(scope, bool) or scope < 0):
        raise BreachInputError("scope_count must be a non-negative integer")
    body = {
        "event_id": str(fields["event_id"]),
        "detected_at": detected_at,
        "data_types": json.dumps(labels),
        "scope_count": -1 if scope is None else scope,
        "note_hash": normalize_note_hash(fields.get("note_hash")),
        "retain_until": retain_until(detected_at),
        "prev_hash": prev_hash or "",
    }
    stored = dict(body)
    stored["entry_hash"] = hash_document(body)
    stored["data_types"] = labels
    stored["scope_count"] = scope
    stored["note_hash"] = body["note_hash"] or None
    return stored


def seal_access(prev_hash: str | None, fields: dict[str, Any]) -> dict[str, Any]:
    body = {
        "access_id": str(fields["access_id"]),
        "at": str(fields["at"]),
        "actor": str(fields["actor"]),
        "action": str(fields["action"]),
        "prev_hash": prev_hash or "",
    }
    body["entry_hash"] = hash_document({key: body[key] for key in ("access_id", "at", "actor", "action", "prev_hash")})
    return body


def chain_ok(events: list[dict[str, Any]]) -> bool:
    prev = ""
    for event in events:
        sealed = seal_breach(
            prev,
            {
                "event_id": event.get("event_id"),
                "detected_at": event.get("detected_at"),
                "data_types": event.get("data_types"),
                "scope_count": event.get("scope_count"),
                "note_hash": event.get("note_hash") or "",
            },
        )
        if event.get("prev_hash") != prev or event.get("entry_hash") != sealed["entry_hash"]:
            return False
        if event.get("retain_until") != sealed["retain_until"]:
            return False
        prev = str(event["entry_hash"])
    return True


def access_chain_ok(events: list[dict[str, Any]]) -> bool:
    prev = ""
    for event in events:
        sealed = seal_access(
            prev,
            {
                "access_id": event.get("access_id"),
                "at": event.get("at"),
                "actor": event.get("actor"),
                "action": event.get("action"),
            },
        )
        if event.get("prev_hash") != prev or event.get("entry_hash") != sealed["entry_hash"]:
            return False
        prev = str(event["entry_hash"])
    return True


def notice_text(data_types: list[str], detected_at: str) -> str:
    labels = ", ".join(data_types)
    return (
        "GAB_\n"
        "A security notice was recorded.\n"
        f"Detected at: {detected_at}\n"
        f"Types of data: {labels}\n"
        "This message does not include the data itself.\n"
        "It is a product notice. It is not a legal determination.\n"
    )
