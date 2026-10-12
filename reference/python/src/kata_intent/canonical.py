# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: Apache-2.0
"""Canonical JSON for KATA mandate signatures.

The encoding follows RFC 8785 for key order and string escaping. Numbers are
base-10 with no exponent, no leading zero, and no trailing fractional zero.
Integer values have no decimal point. ``1``, ``1.0``, and ``1.00`` are the
same number and encode as ``1``.

Language-default JSON serializers are not interchangeable here: many emit
``1.0`` where this encoder emits ``1``, and those two strings do not verify
as the same signature.
"""

from __future__ import annotations

import json
from decimal import Decimal
from typing import Any

from kata_intent.errors import KataError


def canonical_bytes(value: Any) -> bytes:
    """Return the canonical UTF-8 encoding of ``value``."""

    return _encode(value).encode("utf-8")


def _encode(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, Decimal):
        return encode_decimal(value)
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise KataError("non-finite numbers cannot be signed")
        return encode_decimal(Decimal(str(value)))
    if isinstance(value, str):
        return encode_string(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_encode(item) for item in value) + "]"
    if isinstance(value, dict):
        parts: list[str] = []
        for key in sorted(value, key=lambda item: str(item).encode("utf-16-be")):
            if not isinstance(key, str):
                raise KataError("object keys must be strings")
            parts.append(encode_string(key) + ":" + _encode(value[key]))
        return "{" + ",".join(parts) + "}"
    raise KataError(f"cannot canonicalize {type(value).__name__}")


def encode_decimal(value: Decimal) -> str:
    """Encode a decimal as a canonical JSON number token."""

    if not value.is_finite():
        raise KataError("non-finite numbers cannot be signed")
    if value == 0:
        return "0"
    text = format(value, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    if text in ("", "-", "-0"):
        return "0"
    return text


def encode_string(value: str) -> str:
    """Encode a string as a JSON string, including U+2028 and U+2029."""

    encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    return encoded.replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")
