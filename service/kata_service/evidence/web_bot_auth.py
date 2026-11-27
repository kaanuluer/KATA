# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Web Bot Auth evidence verifier.

The signature base is RFC 9421. ``Signature-Agent`` is the directory URL from
the Web Bot Auth draft: an origin uses ``/.well-known/http-message-signatures-directory``.
Keys are read through the evidence JWKS cache. Nonces use the evidence nonce
store. ``created`` and ``expires`` must sit within 60 seconds of the clock.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

from kata_service.evidence.http_sig import (
    HttpSignatureError,
    agent_directory,
    covers_authority,
    covers_signature_agent,
    message_from_material,
    parameter,
    signature_material,
)
from kata_service.evidence.jwks import FetchFailed, JwksRejected, KeyCache, public_jwk, signing_key
from kata_service.evidence.schema import empty_hash, evidence_object, payload_hash
from kata_service.evidence.ssrf import DirectoryRejected
from kata_service.evidence.store import EvidenceStore
from kata_service.evidence.verifier import utc_seconds

SIGNATURE_WINDOW_SECONDS = 60
_WINDOW = timedelta(seconds=SIGNATURE_WINDOW_SECONDS)
_UNVERIFIABLE = frozenset({"directory_url_rejected", "jwks_rejected", "jwks_fetch_failed"})
DIRECTORY_MEDIA_TYPE = "application/http-message-signatures-directory+json"


def ed25519_thumbprint(x: str) -> str:
    """RFC 8037 OKP thumbprint. ``x`` is the JWK member, unchanged."""

    encoded = json.dumps({"crv": "Ed25519", "kty": "OKP", "x": x}, separators=(",", ":"), sort_keys=True)
    digest = hashlib.sha256(encoded.encode("ascii")).digest()
    return _b64url(digest)


def publishable_jwk(value: Any) -> dict[str, Any] | None:
    """Public Ed25519 JWK safe to publish. A private ``d`` is refused."""

    parsed = _load_jwk(value)
    if parsed is None:
        return None
    if parsed.get("alg") == "ed25519" and parsed.get("kty") == "OKP":
        parsed = dict(parsed)
        parsed["alg"] = "EdDSA"
    if parsed.get("kty") == "OKP" and parsed.get("crv") == "Ed25519" and not parsed.get("kid"):
        x = parsed.get("x")
        if not isinstance(x, str):
            return None
        parsed = dict(parsed)
        parsed["kid"] = ed25519_thumbprint(x)
    cleaned = public_jwk(parsed)
    if cleaned is None or cleaned["alg"] != "EdDSA":
        return None
    return cleaned["jwk"]


def directory_response(jwk: Any) -> bytes | None:
    cleaned = publishable_jwk(jwk)
    if cleaned is None:
        return None
    body = {"keys": [cleaned]}
    return json.dumps(body, separators=(",", ":"), sort_keys=True).encode("ascii")


class WebBotAuthVerifier:
    """Ed25519 HTTP message signature bound to a Signature-Agent directory."""

    source = "web-bot-auth"

    def __init__(self, store: EvidenceStore, **deps: Any) -> None:
        self.store = store
        self.cache = KeyCache(
            store,
            fetch=deps.get("fetch"),
            resolve=deps.get("resolve"),
            ttl_seconds=int(deps.get("ttl_seconds", 300)),
            max_entries=int(deps.get("max_entries", 64)),
            max_keys=int(deps.get("max_keys", 8)),
            max_bytes=int(deps.get("max_bytes", 65536)),
            timeout=float(deps.get("timeout", 2.0)),
        )

    def verify(self, material: Mapping[str, Any], *, now: datetime) -> dict[str, Any]:
        moment = utc_seconds(now)
        stamp = _stamp(moment)
        if not isinstance(material, Mapping):
            return self._done(stamp, "invalid", "malformed", empty_hash())
        try:
            message = message_from_material(material)
            label = material.get("label") if isinstance(material.get("label"), str) else None
            base, raw, covered, chosen = signature_material(message, label=label)
        except HttpSignatureError as exc:
            return self._done(stamp, "invalid", exc.reason, empty_hash())
        digest = payload_hash(base.encode("ascii"))
        try:
            self._requirements(covered, chosen)
            self._window(covered, moment)
            directory = agent_directory(message, chosen)
        except HttpSignatureError as exc:
            return self._done(stamp, self._result(exc.reason), exc.reason, digest)
        key_id = parameter(covered, "keyid")
        kid = key_id if isinstance(key_id, str) else ""
        try:
            keys = self.cache.keys_for(directory, kid, moment)
        except DirectoryRejected:
            return self._done(stamp, "unverifiable", "directory_url_rejected", digest)
        except JwksRejected:
            return self._done(stamp, "unverifiable", "jwks_rejected", digest)
        except FetchFailed:
            return self._done(stamp, "unverifiable", "jwks_fetch_failed", digest)
        chosen_key = next((item for item in keys if item["kid"] == kid), None)
        if chosen_key is None:
            return self._done(stamp, "invalid", "unknown_key", digest, key_id=kid)
        if chosen_key["jwk"].get("alg") != "EdDSA":
            return self._done(stamp, "invalid", "alg_rejected", digest, key_id=kid)
        key = signing_key(chosen_key["jwk"])
        if key is None or key.algorithm != "EdDSA" or len(raw) != 64 or not key.verify(base.encode("ascii"), raw):
            return self._done(stamp, "invalid", "signature", digest, key_id=kid)
        nonce = parameter(covered, "nonce")
        expires = parameter(covered, "expires")
        if not isinstance(nonce, str) or not isinstance(expires, int) or isinstance(expires, bool):
            return self._done(stamp, "invalid", "malformed", digest, key_id=kid)
        try:
            expires_at = datetime.fromtimestamp(expires, timezone.utc) + _WINDOW + timedelta(seconds=1)
        except (OverflowError, OSError, ValueError):
            return self._done(stamp, "invalid", "malformed", digest, key_id=kid)
        fresh = self.store.consume_nonce(directory, nonce, now=moment, expires_at=expires_at)
        created = parameter(covered, "created")
        claims = {"created": created, "expires": expires, "tag": "web-bot-auth"}
        if not fresh:
            return self._done(stamp, "invalid", "replay", digest, issuer=directory, subject=kid, key_id=kid, claims=claims)
        return self._done(
            stamp,
            "valid",
            "ok",
            digest,
            issuer=directory,
            subject=kid,
            key_id=kid,
            claims=claims,
        )

    def _requirements(self, covered, label: str) -> None:
        if parameter(covered, "tag") != "web-bot-auth":
            raise HttpSignatureError("tag")
        algorithm = parameter(covered, "alg")
        if algorithm is not None and algorithm != "ed25519":
            raise HttpSignatureError("alg_rejected")
        created = parameter(covered, "created")
        expires = parameter(covered, "expires")
        key_id = parameter(covered, "keyid")
        nonce = parameter(covered, "nonce")
        if isinstance(created, bool) or not isinstance(created, int):
            raise HttpSignatureError("malformed")
        if isinstance(expires, bool) or not isinstance(expires, int):
            raise HttpSignatureError("malformed")
        if not isinstance(key_id, str) or not key_id or len(key_id) > 200:
            raise HttpSignatureError("malformed")
        if not isinstance(nonce, str) or not nonce or len(nonce) > 200:
            raise HttpSignatureError("nonce_missing" if not isinstance(nonce, str) or not nonce else "malformed")
        if created > expires:
            raise HttpSignatureError("malformed")
        if not covers_authority(covered) or not covers_signature_agent(covered, label):
            raise HttpSignatureError("missing_component")

    def _window(self, covered, now: datetime) -> None:
        created = parameter(covered, "created")
        expires = parameter(covered, "expires")
        if not isinstance(created, int) or not isinstance(expires, int) or isinstance(created, bool) or isinstance(expires, bool):
            raise HttpSignatureError("malformed")
        current = int(now.timestamp())
        if created < current - SIGNATURE_WINDOW_SECONDS or expires < current - SIGNATURE_WINDOW_SECONDS:
            raise HttpSignatureError("expired")
        if created > current + SIGNATURE_WINDOW_SECONDS:
            raise HttpSignatureError("not_yet_valid")
        if expires > current + SIGNATURE_WINDOW_SECONDS:
            raise HttpSignatureError("window")

    def _result(self, reason: str) -> str:
        if reason in _UNVERIFIABLE:
            return "unverifiable"
        return "invalid"

    def _done(
        self,
        stamp: str,
        result: str,
        reason: str,
        digest: str,
        *,
        issuer: str = "",
        subject: str = "",
        key_id: str = "",
        claims: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        if result != "valid":
            claims = {}
        if reason == "directory_url_rejected":
            issuer = ""
            subject = ""
            key_id = ""
        return evidence_object(
            source=self.source,
            issuer=issuer if len(issuer) <= 200 else "",
            subject=subject if len(subject) <= 200 else "",
            claims=claims,
            verified_at=stamp,
            key_id=key_id if len(key_id) <= 200 else "",
            result=result,
            reason=reason,
            payload_hash_hex=digest,
        )


def _stamp(now: datetime) -> str:
    return now.strftime("%Y-%m-%dT%H:%M:%SZ")


def _b64url(data: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _load_jwk(value: Any) -> dict[str, Any] | None:
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            value = json.loads(text)
        except json.JSONDecodeError:
            return None
    if not isinstance(value, dict):
        return None
    return value
