# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Keyed identifiers for login email and rate-limit subjects.

GAB_KEYED_IDENTIFIERS and GAB_HMAC_RATE_SUBJECT default off. token_hash of
high-entropy secrets stays plain SHA-256 and is not handled here.

This module does not claim legal compliance or certification.
"""

from __future__ import annotations

from typing import Any

from kata_service.bureau import email_hash, normalize_email, token_hash
from kata_service.keys import KeyCustodyError


class IdentifierMode:
    """HMAC lookup plus envelope encryption for a stored email address."""

    def __init__(self, provider, *, stop_plaintext: bool) -> None:
        if provider is None:
            raise KeyCustodyError("keyed identifiers need a key provider")
        self.provider = provider
        self.stop_plaintext = stop_plaintext

    def candidates(self, email: str) -> list[str]:
        return [token.encode() for token in self.provider.hmac_tokens(normalize_email(email), purpose="identifier")]

    def legacy_digest(self, email: str) -> str:
        return email_hash(email)

    def bind(self, email: str, subject_id: str) -> dict[str, str]:
        normalized = normalize_email(email)
        token = self.provider.hmac(normalized, purpose="identifier")
        sealed = self.provider.seal(normalized.encode("utf-8"), subject_id=subject_id)
        return {
            "email_hash": token.encode() if self.stop_plaintext else email_hash(normalized),
            "email": "" if self.stop_plaintext else normalized,
            "email_hmac": token.encode(),
            "email_kid": token.kid,
            "email_ciphertext": sealed,
        }

    def reveal(self, record: dict[str, Any], subject_id: str) -> dict[str, Any]:
        revealed = dict(record)
        if revealed.get("email"):
            return revealed
        ciphertext = revealed.get("email_ciphertext")
        if not ciphertext:
            return revealed
        try:
            revealed["email"] = self.provider.unseal(ciphertext, subject_id=subject_id).decode("utf-8")
        except KeyCustodyError:
            revealed["email"] = ""
        return revealed


def rate_limit_subject(token: str, host: str | None, *, keyed: bool, provider) -> str:
    """Bearer subjects stay token_hash. A missing bearer uses the client host.

    When keyed is on, the host is HMAC'd with purpose ``rate`` and the raw
    address is not returned. ``anonymous`` is the placeholder when the host
    is missing, and it is HMAC'd too.
    """

    if token:
        return token_hash(token)
    raw = host or "anonymous"
    if not keyed:
        return raw
    if provider is None:
        raise KeyCustodyError("GAB_HMAC_RATE_SUBJECT needs a key provider")
    return provider.hmac(raw, purpose="rate").encode()
