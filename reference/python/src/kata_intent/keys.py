# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: Apache-2.0
"""Signing keys for mandate signatures.

Version 1 accepts two algorithms, named on the mandate:

- ``EdDSA`` — Ed25519 (RFC 8037). The fingerprint is SHA-256 of the raw 32-byte public key.
- ``ES256`` — ECDSA P-256 with SHA-256 (JWS). The fingerprint is SHA-256 of the 64-byte ``x || y``.

JWS signatures for ES256 are the raw 32-byte ``R || S`` encoding, not DER.
The private ``d`` parameter is rejected on every public JWK.
"""

from __future__ import annotations

import base64
import hashlib
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from kata_intent.errors import KataError

ALGORITHMS = frozenset({"EdDSA", "ES256"})
_P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    try:
        return base64.urlsafe_b64decode(value + padding)
    except Exception as exc:  # noqa: BLE001 — surface a single library error
        raise KataError("invalid base64url") from exc


def _fingerprint(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


class PublicKey:
    """An Ed25519 or P-256 public key."""

    def __init__(self, raw: bytes, algorithm: str = "EdDSA"):
        if algorithm not in ALGORITHMS:
            raise KataError(f"unsupported algorithm: {algorithm}")
        self.algorithm = algorithm
        self.raw = raw
        if algorithm == "EdDSA":
            if len(raw) != 32:
                raise KataError("Ed25519 public key must be 32 bytes")
            self._key: Any = Ed25519PublicKey.from_public_bytes(raw)
        else:
            if len(raw) != 64:
                raise KataError("P-256 public key must be 64 bytes")
            x = int.from_bytes(raw[:32], "big")
            y = int.from_bytes(raw[32:], "big")
            self._key = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()

    @property
    def fingerprint(self) -> str:
        return _fingerprint(self.raw)

    def to_jwk(self) -> dict[str, str]:
        if self.algorithm == "EdDSA":
            return {
                "crv": "Ed25519",
                "kid": self.fingerprint,
                "kty": "OKP",
                "x": _b64url(self.raw),
            }
        return {
            "crv": "P-256",
            "kid": self.fingerprint,
            "kty": "EC",
            "x": _b64url(self.raw[:32]),
            "y": _b64url(self.raw[32:]),
        }

    def verify(self, message: bytes, signature: bytes) -> bool:
        try:
            if self.algorithm == "EdDSA":
                self._key.verify(signature, message)
            else:
                if len(signature) != 64:
                    return False
                r = int.from_bytes(signature[:32], "big")
                s = int.from_bytes(signature[32:], "big")
                der = utils.encode_dss_signature(r, s)
                self._key.verify(der, message, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            return False
        except Exception:  # noqa: BLE001 — a malformed ECDSA pair is a failed verification
            return False
        return True


class PrivateKey:
    """A private key for ``EdDSA`` or ``ES256``. The seed is 32 bytes."""

    def __init__(self, seed: bytes, algorithm: str = "EdDSA"):
        if algorithm not in ALGORITHMS:
            raise KataError(f"unsupported algorithm: {algorithm}")
        if len(seed) != 32:
            raise KataError(f"{algorithm} seed must be 32 bytes")
        self.algorithm = algorithm
        self.seed = seed
        if algorithm == "EdDSA":
            self._key: Any = Ed25519PrivateKey.from_private_bytes(seed)
            public_raw = self._key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        else:
            scalar = int.from_bytes(seed, "big")
            if not 1 <= scalar < _P256_ORDER:
                raise KataError("ES256 seed is outside the P-256 scalar range")
            self._key = ec.derive_private_key(scalar, ec.SECP256R1())
            numbers = self._key.public_key().public_numbers()
            public_raw = numbers.x.to_bytes(32, "big") + numbers.y.to_bytes(32, "big")
        self.public = PublicKey(public_raw, algorithm)

    def sign(self, message: bytes) -> bytes:
        if self.algorithm == "EdDSA":
            return self._key.sign(message)
        der = self._key.sign(message, ec.ECDSA(hashes.SHA256()))
        r, s = utils.decode_dss_signature(der)
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def generate_keypair(algorithm: str = "EdDSA") -> PrivateKey:
    """Generate a fresh key for ``algorithm``."""

    if algorithm == "EdDSA":
        generated = Ed25519PrivateKey.generate()
        seed = generated.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        return PrivateKey(seed, "EdDSA")
    if algorithm == "ES256":
        generated = ec.generate_private_key(ec.SECP256R1())
        seed = generated.private_numbers().private_value.to_bytes(32, "big")
        return PrivateKey(seed, "ES256")
    raise KataError(f"unsupported algorithm: {algorithm}")


def private_key_from_seed(seed: bytes, algorithm: str = "EdDSA") -> PrivateKey:
    """Build a key from a 32-byte seed. Demo seeds are public; do not use them for a real principal."""

    return PrivateKey(seed, algorithm)


def public_key_from_jwk(jwk: dict[str, Any]) -> PublicKey:
    """Read a public JWK. A private ``d`` parameter is rejected so it is never stored on a mandate."""

    if not isinstance(jwk, dict):
        raise KataError("JWK must be an object")
    if "d" in jwk:
        raise KataError("refusing a private JWK")
    kty = jwk.get("kty")
    crv = jwk.get("crv")
    if kty == "OKP" and crv == "Ed25519":
        x = jwk.get("x")
        if not isinstance(x, str):
            raise KataError("JWK is missing x")
        key = PublicKey(_b64url_decode(x), "EdDSA")
    elif kty == "EC" and crv == "P-256":
        x = jwk.get("x")
        y = jwk.get("y")
        if not isinstance(x, str) or not isinstance(y, str):
            raise KataError("JWK is missing x or y")
        key = PublicKey(_b64url_decode(x) + _b64url_decode(y), "ES256")
    else:
        raise KataError("JWK must be Ed25519 or P-256")
    kid = jwk.get("kid")
    if kid is not None and kid != key.fingerprint:
        raise KataError("JWK kid does not match the public key fingerprint")
    return key
