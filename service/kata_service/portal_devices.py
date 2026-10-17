# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Devices and passkeys for an individual.

The individual portal does not score a person.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from kata_service.bureau import BureauError, _id
from kata_service.passkeys import (
    CHALLENGE_TTL_SECONDS,
    authentication_options,
    challenge_bytes,
    credential_id,
    decode_key,
    encode_key,
    registration_options,
    verify_assertion,
    verify_registration,
)

STORED = (
    "The email address used to sign in, and a pseudonymous principal id.",
    "For each registered device: a credential id, the public half of the passkey, a sign counter, a label, and the time it was added.",
    "Session tokens are stored as hashes.",
)

_HIDDEN = ("score", "risk", "score_reasons", "model_version")


def individual_view(view: dict[str, Any]) -> dict[str, Any]:
    for key in _HIDDEN:
        view.pop(key, None)
    return view


def registration_challenge(service, auth, origin: str) -> dict[str, Any]:
    service._portal(auth)
    exclude = [decode_key(item["credential_id"]) for item in service.repo.list_passkeys(auth.principal_id or "")]
    challenge, options = registration_options(origin, auth.principal_id or "", exclude)
    _store_challenge(service, auth.principal_id, "register", challenge, origin)
    return options


def register_device(service, auth, body: dict[str, Any], origin: str) -> dict[str, Any]:
    service._portal(auth)
    credential = body.get("credential")
    if not isinstance(credential, dict):
        raise BureauError(400, "credential is required")
    stored = _consume_challenge(service, auth.principal_id, "register", origin, credential)
    verified = verify_registration(origin, challenge_bytes(stored["challenge"]), credential)
    record = {
        "credential_id": encode_key(verified.credential_id),
        "principal_id": auth.principal_id,
        "public_key": encode_key(verified.credential_public_key),
        "sign_count": int(verified.sign_count),
        "label": _label(body.get("label")),
        "created_at": service.stamp(),
        "last_used_at": None,
    }
    service.repo.put_passkey(record)
    return _public_device(record)


def authentication_challenge(service, origin: str) -> dict[str, Any]:
    challenge, options = authentication_options(origin, [])
    _store_challenge(service, None, "authenticate", challenge, origin)
    return options


def authenticate_device(service, credential: dict[str, Any], origin: str) -> dict[str, str]:
    if not isinstance(credential, dict):
        raise BureauError(401, "passkey is not valid")
    record = service.repo.passkey_by_id(credential_id(credential))
    if record is None:
        raise BureauError(401, "passkey is not valid")
    stored = _consume_challenge(service, None, "authenticate", origin, credential)
    verified = verify_assertion(
        origin,
        challenge_bytes(stored["challenge"]),
        credential,
        decode_key(record["public_key"]),
        int(record["sign_count"]),
    )
    service.repo.update_passkey_use(record["credential_id"], int(verified.new_sign_count), service.stamp())
    session = service._session("portal", record["principal_id"])
    return {"token": session, "kind": "portal", "principal_id": record["principal_id"]}


def assertion_challenge(service, auth, origin: str) -> dict[str, Any]:
    service._portal(auth)
    allow = [decode_key(item["credential_id"]) for item in service.repo.list_passkeys(auth.principal_id or "")]
    if not allow:
        raise BureauError(401, "a registered device is required")
    challenge, options = authentication_options(origin, allow)
    _store_challenge(service, auth.principal_id, "assert", challenge, origin)
    return options


def require_assertion(service, auth, assertion: dict[str, Any] | None, origin: str) -> None:
    service._portal(auth)
    if not service.repo.list_passkeys(auth.principal_id or ""):
        raise BureauError(401, "a registered device is required")
    if not isinstance(assertion, dict):
        raise BureauError(401, "a registered device is required")
    record = service.repo.passkey_by_id(credential_id(assertion))
    if record is None or record["principal_id"] != auth.principal_id:
        raise BureauError(401, "a registered device is required")
    stored = _consume_challenge(service, auth.principal_id, "assert", origin, assertion)
    verified = verify_assertion(
        origin,
        challenge_bytes(stored["challenge"]),
        assertion,
        decode_key(record["public_key"]),
        int(record["sign_count"]),
    )
    service.repo.update_passkey_use(record["credential_id"], int(verified.new_sign_count), service.stamp())


def list_devices(service, auth) -> dict[str, Any]:
    service._portal(auth)
    principal_id = auth.principal_id or ""
    return {
        "devices": [_public_device(item) for item in service.repo.list_passkeys(principal_id)],
        "stored": list(STORED),
        "individual_score": False,
    }


def remove_device(service, auth, credential: str, assertion: dict[str, Any] | None, origin: str) -> dict[str, bool]:
    require_assertion(service, auth, assertion, origin)
    if not service.repo.delete_passkey(credential, auth.principal_id or ""):
        raise BureauError(404, "device was not found")
    return {"removed": True}


def _store_challenge(service, principal_id: str | None, kind: str, challenge: bytes, origin: str) -> None:
    expires = (service.now() + timedelta(seconds=CHALLENGE_TTL_SECONDS)).strftime("%Y-%m-%dT%H:%M:%SZ")
    service.repo.put_challenge(
        {
            "challenge_id": _id("wac"),
            "principal_id": principal_id,
            "kind": kind,
            "challenge": encode_key(challenge),
            "rp_id": url_host(origin),
            "origin": origin,
            "expires_at": expires,
            "used_at": None,
        }
    )


def url_host(origin: str) -> str:
    from kata_service.passkeys import relying_party

    return relying_party(origin)


def _consume_challenge(service, principal_id: str | None, kind: str, origin: str, credential: dict[str, Any]) -> dict[str, Any]:
    from kata_service.passkeys import base64url_to_bytes

    raw = credential.get("response")
    if not isinstance(raw, dict) or not isinstance(raw.get("clientDataJSON"), str):
        raise BureauError(401, "passkey challenge is not valid")
    try:
        import json

        client_data = json.loads(base64url_to_bytes(raw["clientDataJSON"]))
        challenge = str(client_data.get("challenge") or "")
    except Exception as exc:
        raise BureauError(401, "passkey challenge is not valid") from exc
    stored = service.repo.take_challenge(kind, challenge, principal_id, origin, service.stamp())
    if stored is None:
        raise BureauError(401, "passkey challenge is not valid")
    return stored


def _label(value: Any) -> str:
    text = " ".join(str(value or "").split())
    if not text:
        return "This device"
    if len(text) > 80:
        raise BureauError(400, "label is too long")
    return text


def _public_device(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "credential_id": record["credential_id"],
        "label": record["label"],
        "created_at": record["created_at"],
        "last_used_at": record.get("last_used_at"),
    }

