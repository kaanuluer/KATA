# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: Apache-2.0
"""Flattened JSON Web Signature (RFC 7515) with EdDSA (RFC 8037).

The protected header and the payload are both KATA canonical JSON.
Verification checks the signature over the exact payload bytes, then
requires those bytes to be canonical.
"""

from __future__ import annotations

import base64
import hmac
from dataclasses import dataclass
from typing import Any

from kata_intent.canonical import canonical_bytes
from kata_intent.keys import PrivateKey, PublicKey


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes | None:
    try:
        padding = "=" * (-len(value) % 4)
        return base64.urlsafe_b64decode(value + padding)
    except Exception:  # noqa: BLE001 — malformed JWS is a failed verification
        return None


@dataclass(frozen=True)
class JwsCheck:
    ok: bool
    payload: dict[str, Any] | None
    payload_bytes: bytes | None
    reason: str | None


def sign_jws(payload: dict[str, Any], private_key: PrivateKey, *, typ: str) -> dict[str, str]:
    """Sign ``payload`` and return a flattened JWS."""

    header = {"alg": "EdDSA", "kid": private_key.public.fingerprint, "typ": typ}
    header_b64 = _b64url(canonical_bytes(header))
    payload_bytes = canonical_bytes(payload)
    payload_b64 = _b64url(payload_bytes)
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    signature = private_key.sign(signing_input)
    return {
        "payload": payload_b64,
        "protected": header_b64,
        "signature": _b64url(signature),
    }


def verify_jws(jws: dict[str, Any], public_key: PublicKey, *, typ: str) -> JwsCheck:
    """Verify a flattened JWS produced by :func:`sign_jws`."""

    if not isinstance(jws, dict):
        return JwsCheck(False, None, None, "malformed")
    protected = jws.get("protected")
    payload_b64 = jws.get("payload")
    signature_b64 = jws.get("signature")
    if not all(isinstance(part, str) for part in (protected, payload_b64, signature_b64)):
        return JwsCheck(False, None, None, "malformed")

    header_bytes = _b64url_decode(protected)
    payload_bytes = _b64url_decode(payload_b64)
    signature = _b64url_decode(signature_b64)
    if header_bytes is None or payload_bytes is None or signature is None:
        return JwsCheck(False, None, None, "malformed")

    try:
        import json

        header = json.loads(header_bytes.decode("utf-8"))
        payload = json.loads(payload_bytes.decode("utf-8"), parse_float=_decimal, parse_int=int)
    except Exception:  # noqa: BLE001
        return JwsCheck(False, None, None, "malformed")

    if not isinstance(header, dict) or header.get("alg") != "EdDSA" or header.get("typ") != typ:
        return JwsCheck(False, None, None, "header")
    if canonical_bytes(header) != header_bytes:
        return JwsCheck(False, None, None, "header")
    if not isinstance(payload, dict):
        return JwsCheck(False, None, None, "malformed")
    if canonical_bytes(payload) != payload_bytes:
        return JwsCheck(False, None, None, "noncanonical")

    kid = header.get("kid")
    if kid is not None and kid != public_key.fingerprint:
        return JwsCheck(False, None, None, "kid")

    signing_input = f"{protected}.{payload_b64}".encode("ascii")
    if not public_key.verify(signing_input, signature):
        return JwsCheck(False, None, None, "signature")
    return JwsCheck(True, payload, payload_bytes, None)


def same_bytes(left: bytes, right: bytes) -> bool:
    return hmac.compare_digest(left, right)


def _decimal(value: str):
    from decimal import Decimal

    return Decimal(value)
