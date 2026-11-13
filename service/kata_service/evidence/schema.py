# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Evidence object returned by every verifier.

The result is valid, invalid, or unverifiable. Those words are not KATA decisions.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, Mapping

RESULTS = frozenset({"valid", "invalid", "unverifiable"})
CLOCK_SKEW_SECONDS = 60
_STAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_HASH = re.compile(r"^[0-9a-f]{64}$")
_FIELDS = (
    "source",
    "issuer",
    "subject",
    "claims",
    "verified_at",
    "key_id",
    "result",
    "reason",
    "payload_hash",
)
# Claim names that would hold a government identifier. The value is never stored.
SENSITIVE_CLAIM_NAMES = frozenset(
    {
        "aadhaar",
        "drivers_license",
        "driver_license",
        "government_id",
        "itin",
        "national_id",
        "nino",
        "passport",
        "passport_number",
        "sin",
        "social_security",
        "ssn",
        "tax_id",
    }
)
_MAX_CLAIMS = 16
_MAX_CLAIM_STRING = 200


class EvidenceSchemaError(ValueError):
    """The evidence object does not match the shared shape."""


def payload_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def empty_hash() -> str:
    return payload_hash(b"")


def sanitize_claims(payload: Mapping[str, Any]) -> tuple[dict[str, Any], str | None]:
    """Keep scalar claims. A government-identifier name drops every claim."""

    names = {str(key).lower() for key in payload}
    if names & SENSITIVE_CLAIM_NAMES:
        return {}, "sensitive_claim"
    kept: dict[str, Any] = {}
    for key in payload:
        if len(kept) >= _MAX_CLAIMS:
            break
        name = str(key)
        if not name or len(name) > 64:
            continue
        value = payload[key]
        if isinstance(value, bool) or value is None or isinstance(value, (int, float, str)):
            if isinstance(value, str) and len(value) > _MAX_CLAIM_STRING:
                continue
            if isinstance(value, float) and value != value:  # NaN
                continue
            kept[name] = value
    return kept, None


def parse_evidence(value: Mapping[str, Any]) -> dict[str, Any]:
    """Return a copy of a valid evidence object. Extra keys are refused."""

    if not isinstance(value, Mapping):
        raise EvidenceSchemaError("evidence must be an object")
    unknown = set(value) - set(_FIELDS)
    if unknown:
        raise EvidenceSchemaError("evidence has an unknown field")
    missing = [name for name in _FIELDS if name not in value]
    if missing:
        raise EvidenceSchemaError("evidence is missing a field")
    source = value["source"]
    issuer = value["issuer"]
    subject = value["subject"]
    claims = value["claims"]
    verified_at = value["verified_at"]
    key_id = value["key_id"]
    result = value["result"]
    reason = value["reason"]
    digest = value["payload_hash"]
    if not isinstance(source, str) or not 1 <= len(source) <= 64:
        raise EvidenceSchemaError("source is not valid")
    if not isinstance(issuer, str) or len(issuer) > 200:
        raise EvidenceSchemaError("issuer is not valid")
    if not isinstance(subject, str) or len(subject) > 200:
        raise EvidenceSchemaError("subject is not valid")
    if not isinstance(key_id, str) or len(key_id) > 200:
        raise EvidenceSchemaError("key_id is not valid")
    if result not in RESULTS:
        raise EvidenceSchemaError("result is not valid, invalid, or unverifiable")
    if not isinstance(reason, str) or not 1 <= len(reason) <= 80:
        raise EvidenceSchemaError("reason is not valid")
    if not isinstance(verified_at, str) or _STAMP.match(verified_at) is None:
        raise EvidenceSchemaError("verified_at is not valid")
    if not isinstance(digest, str) or _HASH.match(digest) is None:
        raise EvidenceSchemaError("payload_hash is not valid")
    if not isinstance(claims, dict) or len(claims) > _MAX_CLAIMS:
        raise EvidenceSchemaError("claims is not valid")
    cleaned, sensitive = sanitize_claims(claims)
    if sensitive is not None or cleaned.keys() != claims.keys():
        raise EvidenceSchemaError("claims is not valid")
    return {
        "source": source,
        "issuer": issuer,
        "subject": subject,
        "claims": cleaned,
        "verified_at": verified_at,
        "key_id": key_id,
        "result": result,
        "reason": reason,
        "payload_hash": digest,
    }


def evidence_object(
    *,
    source: str,
    verified_at: str,
    result: str,
    reason: str,
    payload_hash_hex: str,
    issuer: str = "",
    subject: str = "",
    claims: Mapping[str, Any] | None = None,
    key_id: str = "",
) -> dict[str, Any]:
    return parse_evidence(
        {
            "source": source,
            "issuer": issuer,
            "subject": subject,
            "claims": dict(claims or {}),
            "verified_at": verified_at,
            "key_id": key_id,
            "result": result,
            "reason": reason,
            "payload_hash": payload_hash_hex,
        }
    )
