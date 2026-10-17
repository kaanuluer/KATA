# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Devices, passkeys, and step-up approvals for an individual.

The individual portal does not score a person. Approval notices use one
fixed sentence.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from kata_intent.values import hash_document

from kata_service.bureau import BureauError, _id
from kata_service.passkeys import (
    CHALLENGE_TTL_SECONDS,
    authentication_options,
    challenge_bytes,
    credential_id,
    decode_key,
    deliver_web_push,
    encode_key,
    push_text,
    registration_options,
    verify_assertion,
    verify_registration,
)

STORED = (
    "The email address used to sign in, and a pseudonymous principal id.",
    "For each registered device: a credential id, the public half of the passkey, a sign counter, a label, and the time it was added.",
    "A browser push address, and the keys the browser issued for that address, only after explicit consent.",
    "A short-lived approval record bound to one action, only while approval notices are on. The action text is removed when the approval is used or expires.",
    "Session tokens are stored as hashes.",
)

_HIDDEN = ("score", "risk", "score_reasons", "model_version")


def individual_view(view: dict[str, Any]) -> dict[str, Any]:
    for key in _HIDDEN:
        view.pop(key, None)
    return view


def queue_step_up(service, agent: dict[str, Any], action: dict[str, Any] | None) -> None:
    if not service.step_up_approval or not isinstance(action, dict):
        return
    principal_id = agent.get("principal_id")
    if not principal_id:
        return
    digest = hash_document(action)
    now = service.stamp()
    if service.repo.pending_approval(principal_id, digest, now) is not None:
        return
    expires = (service.now() + timedelta(seconds=service.approval_ttl_seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")
    service.repo.put_approval(
        {
            "approval_id": _id("apr"),
            "principal_id": principal_id,
            "action_hash": digest,
            "action": action,
            "status": "pending",
            "expires_at": expires,
            "used_at": None,
            "created_at": now,
        }
    )
    devices = [item for item in service.repo.list_push(principal_id) if item.get("consent_at")]
    if not devices:
        return
    text = push_text()
    for device in devices:
        service.push_outbox.append({"endpoint": device["endpoint"], "body": text})
        try:
            deliver_web_push(
                device,
                text,
                public_key=service.vapid_public_key,
                private_key=service.vapid_private_key,
                subject=service.vapid_subject,
            )
        except Exception:
            service.push_outbox[-1]["delivery"] = "not_delivered"


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
    challenge, options = authentication_options(origin, [], discoverable=True)
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
        require_user_verification=False,
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
        "push_devices": [_public_push(item) for item in service.repo.list_push(principal_id)],
        "stored": list(STORED),
        "individual_score": False,
    }


def remove_device(service, auth, credential: str, assertion: dict[str, Any] | None, origin: str) -> dict[str, bool]:
    require_assertion(service, auth, assertion, origin)
    if not service.repo.delete_passkey(credential, auth.principal_id or ""):
        raise BureauError(404, "device was not found")
    return {"removed": True}


def register_push(service, auth, body: dict[str, Any]) -> dict[str, Any]:
    service._portal(auth)
    if body.get("consent") is not True:
        raise BureauError(400, "push registration needs consent")
    endpoint = str(body.get("endpoint") or "").strip()
    if not endpoint.startswith("https://") or len(endpoint) > 500:
        raise BureauError(400, "push endpoint must be https")
    keys = body.get("keys")
    if not isinstance(keys, dict):
        raise BureauError(400, "push keys are required")
    p256dh = str(keys.get("p256dh") or "")
    auth_secret = str(keys.get("auth") or "")
    if not p256dh or not auth_secret or len(p256dh) > 200 or len(auth_secret) > 200:
        raise BureauError(400, "push keys are required")
    device_id = _id("psh")
    supplied_credential = body.get("credential_id")
    if supplied_credential and str(supplied_credential) == device_id:
        raise BureauError(400, "device id must not equal a passkey credential id")
    if service.consent_events_enabled and service.consent_push:
        version = str(body.get("text_version") or "") or None
        service._append_consent(
            auth.principal_id or "",
            "push",
            True,
            text_version=version,
            source_ref=device_id,
        )
    record = {
        "device_id": device_id,
        "principal_id": auth.principal_id,
        "endpoint": endpoint,
        "p256dh": p256dh,
        "auth_secret": auth_secret,
        "consent_at": service.stamp(),
        "created_at": service.stamp(),
    }
    service.repo.put_push(record)
    return _public_push(record)


def remove_push(service, auth, device_id: str, assertion: dict[str, Any] | None, origin: str) -> dict[str, bool]:
    require_assertion(service, auth, assertion, origin)
    if not service.repo.delete_push(device_id, auth.principal_id or ""):
        raise BureauError(404, "push device was not found")
    return {"removed": True}


def push_public_key(service, auth) -> dict[str, str]:
    service._portal(auth)
    if not service.step_up_approval or not service.vapid_public_key:
        raise BureauError(404, "push is off")
    return {"public_key": service.vapid_public_key}


def list_approvals(service, auth) -> list[dict[str, Any]]:
    service._portal(auth)
    _require_flag(service)
    now = service.stamp()
    rows = []
    for item in service.repo.list_approvals(auth.principal_id or ""):
        rows.append(_public_approval(_settle(service, item, now), now))
    return rows


def decide_approval(service, auth, approval_id: str, decision: str, assertion: dict[str, Any] | None, origin: str) -> dict[str, str]:
    _require_flag(service)
    require_assertion(service, auth, assertion, origin)
    record = service.repo.get_approval(approval_id)
    if record is None or record["principal_id"] != auth.principal_id:
        raise BureauError(404, "approval was not found")
    now = service.stamp()
    if record.get("used_at") or record["status"] != "pending":
        raise BureauError(409, "approval was already used")
    if record["expires_at"] < now:
        record["status"] = "expired"
        record["action"] = None
        record["used_at"] = now
        service.repo.save_approval(record)
        raise BureauError(410, "approval has expired")
    record["status"] = decision
    record["used_at"] = now
    record["action"] = None
    service.repo.save_approval(record)
    return {"approval_id": approval_id, "status": decision}


def _require_flag(service) -> None:
    if not service.step_up_approval:
        raise BureauError(404, "step-up approval is off")


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
    except Exception:
        raise BureauError(401, "passkey challenge is not valid") from None
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


def _public_push(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "device_id": record["device_id"],
        "endpoint": record["endpoint"],
        "consent_at": record["consent_at"],
        "created_at": record["created_at"],
    }


def _settle(service, record: dict[str, Any], now: str) -> dict[str, Any]:
    if record["status"] == "pending" and record["expires_at"] < now:
        record["status"] = "expired"
        record["action"] = None
        record["used_at"] = record.get("used_at") or now
        service.repo.save_approval(record)
    return record


def _public_approval(record: dict[str, Any], now: str) -> dict[str, Any]:
    pending = record["status"] == "pending" and record["expires_at"] >= now and record.get("action")
    view: dict[str, Any] = {
        "approval_id": record["approval_id"],
        "status": record["status"],
        "expires_at": record["expires_at"],
        "created_at": record["created_at"],
    }
    if pending:
        view["action"] = record["action"]
    return view
