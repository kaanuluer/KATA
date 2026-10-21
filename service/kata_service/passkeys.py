# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Passkey ceremonies and the fixed approval push sentence.

The push sender accepts one sentence. Merchant, amount, and agent name never
enter that sentence.

``GAB_PASSKEY_ENROLLMENT`` defaults off. When it is on, registration prefers
the platform authenticator on this device: Touch ID or iCloud Keychain on a
Mac, Windows Hello, or the phone's own authenticator. The resident key is
required so the passkey can be used with an empty allow list. User verification
is preferred, so a Mac without Touch ID can still enroll. Sign-in uses that
discoverable credential and does not send an allow list. With the flag off,
registration and sign-in still require user verification. The relying party id
stays the hostname, so a passkey already registered on this host still matches.
Browser UI is not guaranteed; the portal script adds a client-device hint only
when that browser accepts hints and the flag is on.
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
    AuthenticatorAttachment,
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


def registration_options(
    origin: str, principal_id: str, exclude: list[bytes], *, enrollment: bool = False
) -> tuple[bytes, dict[str, Any]]:
    """Options for registering a passkey.

    Enrollment asks for the platform authenticator and preferred user
    verification, and leaves hints off the payload. The portal adds
    ``client-device`` only after the browser shows that it keeps that member.
    The default keeps required user verification and does not set an attachment.
    """

    selection = AuthenticatorSelectionCriteria(
        resident_key=ResidentKeyRequirement.REQUIRED,
        user_verification=(
            UserVerificationRequirement.PREFERRED if enrollment else UserVerificationRequirement.REQUIRED
        ),
    )
    if enrollment:
        selection.authenticator_attachment = AuthenticatorAttachment.PLATFORM
    options = generate_registration_options(
        rp_id=relying_party(origin),
        rp_name="Global Agent Bureau",
        user_name=principal_id,
        user_id=principal_id.encode("utf-8"),
        user_display_name="Individual",
        authenticator_selection=selection,
        exclude_credentials=[PublicKeyCredentialDescriptor(id=item) for item in exclude],
    )
    payload = json.loads(options_to_json(options))
    if enrollment:
        payload.pop("hints", None)
    return options.challenge, payload


def authentication_options(
    origin: str, allow: list[bytes], *, discoverable: bool = False, strip_hints: bool = False
) -> tuple[bytes, dict[str, Any]]:
    """Options for a sign-in or a step-up assertion.

    Discoverable sign-in omits ``allowCredentials`` so the browser can offer a
    passkey stored on this device, and it asks for preferred user verification.
    A step-up check still names the credentials already registered to the
    signed-in principal, and it still asks for user verification. Hints are
    removed only when enrollment asked for that.
    """

    if discoverable:
        verification = UserVerificationRequirement.PREFERRED
    else:
        verification = UserVerificationRequirement.REQUIRED
    options = generate_authentication_options(
        rp_id=relying_party(origin),
        allow_credentials=[PublicKeyCredentialDescriptor(id=item) for item in allow] or None,
        user_verification=verification,
    )
    payload = json.loads(options_to_json(options))
    if discoverable:
        payload.pop("allowCredentials", None)
    if discoverable or strip_hints:
        payload.pop("hints", None)
    return options.challenge, payload


def verify_registration(
    origin: str, challenge: bytes, credential: dict[str, Any], *, require_user_verification: bool = True
):
    try:
        return verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=relying_party(origin),
            expected_origin=origin,
            require_user_verification=require_user_verification,
        )
    except (WebAuthnException, ValueError, KeyError):
        raise BureauError(401, "passkey is not valid") from None


def verify_assertion(
    origin: str,
    challenge: bytes,
    credential: dict[str, Any],
    public_key: bytes,
    sign_count: int,
    *,
    require_user_verification: bool = True,
):
    try:
        return verify_authentication_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=relying_party(origin),
            expected_origin=origin,
            credential_public_key=public_key,
            credential_current_sign_count=sign_count,
            require_user_verification=require_user_verification,
        )
    except (WebAuthnException, ValueError, KeyError):
        raise BureauError(401, "passkey is not valid") from None


def credential_id(credential: dict[str, Any]) -> str:
    raw = credential.get("id")
    if not isinstance(raw, str) or not raw:
        raise BureauError(401, "passkey is not valid")
    return raw


def challenge_bytes(stored: str) -> bytes:
    try:
        return base64url_to_bytes(stored)
    except Exception:
        raise BureauError(401, "passkey challenge is not valid") from None


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
