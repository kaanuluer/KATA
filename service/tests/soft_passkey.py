# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""A software passkey for tests. It is not a browser authenticator."""

from __future__ import annotations

import hashlib
import json
import secrets

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from webauthn.helpers import bytes_to_base64url
from webauthn.helpers.encode_cbor import encode_cbor


class SoftPasskey:
    def __init__(self) -> None:
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.cred_id = secrets.token_bytes(16)
        self.sign_count = 0

    def registration(self, options: dict, origin: str, *, verified: bool = True) -> dict:
        numbers = self.key.public_key().public_numbers()
        cose = encode_cbor(
            {1: 2, 3: -7, -1: 1, -2: numbers.x.to_bytes(32, "big"), -3: numbers.y.to_bytes(32, "big")}
        )
        auth_data = _auth_data(options["rp"]["id"], _flags(0x40, verified), 0) + (b"\x00" * 16)
        auth_data += len(self.cred_id).to_bytes(2, "big") + self.cred_id + cose
        attestation = encode_cbor({"fmt": "none", "attStmt": {}, "authData": auth_data})
        client_data = _client_data("webauthn.create", options["challenge"], origin)
        return {
            "id": bytes_to_base64url(self.cred_id),
            "rawId": bytes_to_base64url(self.cred_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": bytes_to_base64url(client_data),
                "attestationObject": bytes_to_base64url(attestation),
            },
        }

    def authentication(self, options: dict, origin: str, *, verified: bool = True) -> dict:
        self.sign_count += 1
        auth_data = _auth_data(options["rpId"], _flags(0, verified), self.sign_count)
        client_data = _client_data("webauthn.get", options["challenge"], origin)
        signature = self.key.sign(auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256()))
        return {
            "id": bytes_to_base64url(self.cred_id),
            "rawId": bytes_to_base64url(self.cred_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": bytes_to_base64url(client_data),
                "authenticatorData": bytes_to_base64url(auth_data),
                "signature": bytes_to_base64url(signature),
                "userHandle": bytes_to_base64url(b"prn_owner"),
            },
        }


def origin_of(client) -> str:
    return str(client.base_url).rstrip("/")


def bind_device(client, token: str, label: str = "Phone") -> SoftPasskey:
    from test_bureau import _auth

    options = client.post("/v1/portal/passkeys/register/options", headers=_auth(token))
    assert options.status_code == 200, options.text
    soft = SoftPasskey()
    saved = client.post(
        "/v1/portal/passkeys",
        headers=_auth(token),
        json={"label": label, "credential": soft.registration(options.json(), origin_of(client))},
    )
    assert saved.status_code == 200, saved.text
    assert saved.json()["label"] == label
    assert "public_key" not in saved.json()
    return soft


def assertion_for(client, token: str, soft: SoftPasskey) -> dict:
    from test_bureau import _auth

    options = client.post("/v1/portal/passkeys/assert/options", headers=_auth(token))
    assert options.status_code == 200, options.text
    return soft.authentication(options.json(), origin_of(client))


def _flags(extra: int, verified: bool) -> int:
    flags = 0x01 | extra
    if verified:
        flags |= 0x04
    return flags


def _auth_data(rp_id: str, flags: int, sign_count: int) -> bytes:
    return hashlib.sha256(rp_id.encode()).digest() + bytes([flags]) + sign_count.to_bytes(4, "big")


def _client_data(kind: str, challenge: str, origin: str) -> bytes:
    return json.dumps(
        {"type": kind, "challenge": challenge, "origin": origin, "crossOrigin": False},
        separators=(",", ":"),
    ).encode()
