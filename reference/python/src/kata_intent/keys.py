# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: Apache-2.0
"""Ed25519 keys for mandate signatures.

Fingerprints are ``sha256:`` plus the lowercase hex SHA-256 of the raw
32-byte public key. The JWK form is an OKP key as in RFC 8037, without the
private ``d`` parameter.
"""

from __future__ import annotations

import base64
import hashlib
from typing import Any

from cryptography.exceptions import InvalidSignature
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


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    try:
        return base64.urlsafe_b64decode(value + padding)
    except Exception as exc:  # noqa: BLE001 — surface a single library error
        raise KataError("invalid base64url") from exc


class PublicKey:
    """An Ed25519 public key."""

    def __init__(self, raw: bytes):
        if len(raw) != 32:
            raise KataError("Ed25519 public key must be 32 bytes")
        self.raw = raw
        self._key = Ed25519PublicKey.from_public_bytes(raw)

    @property
    def fingerprint(self) -> str:
        return "sha256:" + hashlib.sha256(self.raw).hexdigest()

    def to_jwk(self) -> dict[str, str]:
        return {
            "crv": "Ed25519",
            "kid": self.fingerprint,
            "kty": "OKP",
            "x": _b64url(self.raw),
        }

    def verify(self, message: bytes, signature: bytes) -> bool:
        try:
            self._key.verify(signature, message)
        except InvalidSignature:
            return False
        return True


class PrivateKey:
    """An Ed25519 private key. The seed is the 32-byte RFC 8037 private scalar seed."""

    def __init__(self, seed: bytes):
        if len(seed) != 32:
            raise KataError("Ed25519 seed must be 32 bytes")
        self.seed = seed
        self._key = Ed25519PrivateKey.from_private_bytes(seed)
        public_raw = self._key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.public = PublicKey(public_raw)

    def sign(self, message: bytes) -> bytes:
        return self._key.sign(message)


def generate_keypair() -> PrivateKey:
    """Generate a fresh Ed25519 key."""

    generated = Ed25519PrivateKey.generate()
    seed = generated.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    return PrivateKey(seed)


def private_key_from_seed(seed: bytes) -> PrivateKey:
    """Build a key from a 32-byte seed. Demo seeds are public; do not use them for a real principal."""

    return PrivateKey(seed)


def public_key_from_jwk(jwk: dict[str, Any]) -> PublicKey:
    """Read a public OKP JWK. A private ``d`` parameter is rejected so it is never stored on a mandate."""

    if not isinstance(jwk, dict):
        raise KataError("JWK must be an object")
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        raise KataError("only Ed25519 OKP keys are accepted")
    if "d" in jwk:
        raise KataError("refusing a private JWK")
    x = jwk.get("x")
    if not isinstance(x, str):
        raise KataError("JWK is missing x")
    key = PublicKey(_b64url_decode(x))
    kid = jwk.get("kid")
    if kid is not None and kid != key.fingerprint:
        raise KataError("JWK kid does not match the public key fingerprint")
    return key
