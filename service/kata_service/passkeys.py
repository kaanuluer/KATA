# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Passkey ceremonies and the fixed approval push sentence.

The push sender accepts one sentence. Merchant, amount, and agent name never
enter that sentence.
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlparse

from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.exceptions import WebAuthnException
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from kata_service.bureau import BureauError

PUSH_TEXT = "an agent is waiting for your approval, open to review"
CHALLENGE_TTL_SECONDS = 300


def push_text() -> str:
    return PUSH_TEXT


def require_push_text(text: str) -> str:
    if text != PUSH_TEXT:
        raise BureauError(500, "push text is fixed")
    return text


def relying_party(origin: str) -> str:
    host = urlparse(origin).hostname or ""
    if not host:
        raise BureauError(400, "origin is required")
    return host


def registration_options(origin: str, principal_id: str, exclude: list[bytes]) -> tuple[bytes, dict[str, Any]]:
    options = generate_registration_options(
        rp_id=relying_party(origin),
        rp_name="Global Agent Bureau",
        user_name=principal_id,
        user_id=principal_id.encode("utf-8"),
        user_display_name="Individual",
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.REQUIRED,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
        exclude_credentials=[PublicKeyCredentialDescriptor(id=item) for item in exclude],
    )
    return options.challenge, json.loads(options_to_json(options))


def authentication_options(origin: str, allow: list[bytes]) -> tuple[bytes, dict[str, Any]]:
    options = generate_authentication_options(
        rp_id=relying_party(origin),
        allow_credentials=[PublicKeyCredentialDescriptor(id=item) for item in allow] or None,
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    return options.challenge, json.loads(options_to_json(options))


def verify_registration(origin: str, challenge: bytes, credential: dict[str, Any]):
    try:
        return verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=relying_party(origin),
            expected_origin=origin,
            require_user_verification=True,
        )
    except (WebAuthnException, ValueError, KeyError) as exc:
        raise BureauError(401, "passkey is not valid") from exc


def verify_assertion(origin: str, challenge: bytes, credential: dict[str, Any], public_key: bytes, sign_count: int):
    try:
        return verify_authentication_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=relying_party(origin),
            expected_origin=origin,
            credential_public_key=public_key,
            credential_current_sign_count=sign_count,
            require_user_verification=True,
        )
    except (WebAuthnException, ValueError, KeyError) as exc:
        raise BureauError(401, "passkey is not valid") from exc


def credential_id(credential: dict[str, Any]) -> str:
    raw = credential.get("id")
    if not isinstance(raw, str) or not raw:
        raise BureauError(401, "passkey is not valid")
    return raw


def challenge_bytes(stored: str) -> bytes:
    try:
        return base64url_to_bytes(stored)
    except Exception as exc:
        raise BureauError(401, "passkey challenge is not valid") from exc


def encode_key(value: bytes) -> str:
    return bytes_to_base64url(value)


def decode_key(value: str) -> bytes:
    return base64url_to_bytes(value)


def deliver_web_push(
    device: dict[str, Any],
    text: str,
    *,
    public_key: str | None,
    private_key: str | None,
    subject: str | None,
) -> str:
    """Send the fixed sentence, or report that the host has no push keys.

    The text is checked before the device is read, so a merchant, amount, or
    agent name cannot be substituted.
    """

    require_push_text(text)
    if not public_key or not private_key:
        return "not_configured"
    try:
        from pywebpush import webpush
    except ImportError:
        return "not_configured"
    webpush(
        subscription_info={
            "endpoint": device["endpoint"],
            "keys": {"p256dh": device["p256dh"], "auth": device["auth_secret"]},
        },
        data=text,
        vapid_private_key=private_key,
        vapid_claims={"sub": subject or "mailto:info@globalagentbureau.com"},
    )
    return "sent"
