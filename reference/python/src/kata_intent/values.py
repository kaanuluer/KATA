# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: Apache-2.0
"""Shared parsers for amounts, times, and hashes."""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any

from kata_intent.canonical import canonical_bytes
from kata_intent.errors import KataError

CURRENCY = re.compile(r"^[A-Z]{3}$")
FREQUENCY = frozenset({"agreement", "P1D", "P7D", "P1M"})
MONEY_PURPOSES = frozenset({"purchase", "payment", "transfer", "booking", "investment"})
ACK_ROLES = frozenset({"agent", "merchant", "psp", "issuer"})
ACTOR_ROLES = frozenset({"principal", "agent", "merchant", "psp", "issuer", "policy"})


def money(value: Any) -> Decimal:
    """Parse a major-unit amount. Floats are accepted only via their shortest decimal string."""

    if isinstance(value, bool) or value is None:
        raise KataError("amount must be a number")
    if isinstance(value, Decimal):
        amount = value
    elif isinstance(value, int):
        amount = Decimal(value)
    elif isinstance(value, float):
        amount = Decimal(str(value))
    elif isinstance(value, str):
        amount = Decimal(value)
    else:
        raise KataError("amount must be a number")
    if not amount.is_finite():
        raise KataError("amount must be finite")
    return amount


def prefixed_hash(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def hash_document(document: dict[str, Any]) -> str:
    return prefixed_hash(canonical_bytes(document))


def text_hash(text: str) -> str:
    return prefixed_hash(text.encode("utf-8"))


def parse_time(value: str) -> datetime:
    """Parse an RFC 3339 timestamp. Naive timestamps are rejected."""

    if not isinstance(value, str) or not value:
        raise KataError("timestamp must be a string")
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise KataError(f"invalid timestamp: {value}") from exc
    if parsed.tzinfo is None:
        raise KataError("timestamps must include a timezone")
    return parsed.astimezone(timezone.utc)


def as_time(value: str | datetime) -> str:
    """Normalize a timestamp to UTC Zulu form."""

    parsed = value if isinstance(value, datetime) else parse_time(value)
    if parsed.tzinfo is None:
        raise KataError("timestamps must include a timezone")
    parsed = parsed.astimezone(timezone.utc)
    if parsed.microsecond:
        fraction = f"{parsed.microsecond:06d}".rstrip("0")
        return parsed.strftime("%Y-%m-%dT%H:%M:%S") + f".{fraction}Z"
    return parsed.strftime("%Y-%m-%dT%H:%M:%SZ")


def require_text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise KataError(f"{label} must be a non-empty string")
    return value


def coerce(value: Any) -> Any:
    """Convert floats that arrived from ``json.loads`` into decimals."""

    if isinstance(value, float):
        return Decimal(str(value))
    if isinstance(value, list):
        return [coerce(item) for item in value]
    if isinstance(value, dict):
        return {str(key): coerce(item) for key, item in value.items()}
    return value
