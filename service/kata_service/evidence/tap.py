# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Visa Trusted Agent Protocol evidence verifier.

The signature base is the existing RFC 9421 implementation in ``http_sig``.
This module adds the TAP checks from the published sample
(https://github.com/visa/trusted-agent-protocol): covered components
``@authority`` and ``@path``; parameters ``created``, ``expires``, ``nonce``,
the RFC 9421 ``keyid`` parameter, ``alg``, and ``tag``. ``tag`` is
``agent-browser-auth`` or ``agent-payer-auth``. ``alg`` for this verifier is
``ed25519``. ``rsa-pss-sha256`` is named by the sample and is rejected here.

``created`` may be at most 60 seconds ahead of the clock. ``expires`` must not
be before the clock. A nonce is accepted once, through the evidence nonce
store. Public keys come from the caller. Nothing is fetched.

The verifier does nothing unless ``tap_verify`` is true. ``GAB_TAP_VERIFY``
defaults off.
"""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping
from urllib.parse import urlsplit

from kata_intent.keys import PublicKey

from kata_service.evidence.http_sig import (
    HttpSignatureError,
    message_from_material,
    parameter,
    signature_material,
)
from kata_service.evidence.schema import empty_hash, evidence_object, payload_hash
from kata_service.evidence.store import EvidenceStore
from kata_service.evidence.structured_fields import InnerList, Item
from kata_service.evidence.verifier import utc_seconds

TAP_TAGS = frozenset({"agent-browser-auth", "agent-payer-auth"})
CREATED_SKEW_SECONDS = 60
NONCE_ISSUER = "tap"
_KEY_ID = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
_MAX_KEYS = 32
_UNIX_LIMIT = 10_000_000_000
_RECORD_FIELDS = frozenset({"key_id", "algorithm", "public_key", "is_active", "agent_domain", "description"})


@dataclass(frozen=True)
class _TapKey:
    key_id: str
    public: PublicKey
    active: bool
    domain: str


class TapVerifier:
    """Ed25519 TAP signature over the shared RFC 9421 signature base."""

    source = "tap"

    def __init__(self, store: EvidenceStore, **deps: Any) -> None:
        self.store = store
        self.enabled = bool(deps.get("tap_verify"))
        self._keys = _index(deps.get("tap_keys"))

    def verify(self, material: Mapping[str, Any], *, now: datetime) -> dict[str, Any]:
        moment = utc_seconds(now)
        stamp = _stamp(moment)
        if not self.enabled:
            return self._done(stamp, "unverifiable", "unsupported_verifier", empty_hash())
        if not isinstance(material, Mapping):
            return self._done(stamp, "invalid", "malformed", empty_hash())
        try:
            message = message_from_material(material)
            label = material.get("label") if isinstance(material.get("label"), str) else None
            base, raw, covered, _chosen = signature_material(message, label=label)
        except HttpSignatureError as exc:
            return self._done(stamp, "invalid", exc.reason, empty_hash())
        digest = payload_hash(base.encode("ascii"))
        try:
            self._requirements(covered)
            self._window(covered, moment)
        except HttpSignatureError as exc:
            return self._done(stamp, "invalid", exc.reason, digest)
        key_id = parameter(covered, "keyid")
        kid = key_id if isinstance(key_id, str) else ""
        chosen = self._keys.get(kid)
        if chosen is None:
            return self._done(stamp, "invalid", "unknown_key", digest, key_id=kid)
        if not chosen.active:
            return self._done(stamp, "invalid", "inactive_key", digest, key_id=kid)
        if len(raw) != 64 or not chosen.public.verify(base.encode("ascii"), raw):
            return self._done(stamp, "invalid", "signature", digest, key_id=kid)
        nonce = parameter(covered, "nonce")
        expires = parameter(covered, "expires")
        created = parameter(covered, "created")
        if not isinstance(nonce, str) or isinstance(expires, bool) or not isinstance(expires, int):
            return self._done(stamp, "invalid", "malformed", digest, key_id=kid)
        if isinstance(created, bool) or not isinstance(created, int):
            return self._done(stamp, "invalid", "malformed", digest, key_id=kid)
        try:
            expires_at = datetime.fromtimestamp(expires, timezone.utc) + timedelta(seconds=1)
        except (OverflowError, OSError, ValueError):
            return self._done(stamp, "invalid", "malformed", digest, key_id=kid)
        fresh = self.store.consume_nonce(NONCE_ISSUER, nonce, now=moment, expires_at=expires_at)
        tag = parameter(covered, "tag")
        claims = {"alg": "ed25519", "created": created, "expires": expires, "tag": tag}
        if not fresh:
            return self._done(stamp, "invalid", "replay", digest, issuer=chosen.domain, subject=kid, key_id=kid)
        return self._done(
            stamp,
            "valid",
            "ok",
            digest,
            issuer=chosen.domain,
            subject=kid,
            key_id=kid,
            claims=claims,
        )

    def _requirements(self, covered: InnerList) -> None:
        if parameter(covered, "tag") not in TAP_TAGS:
            raise HttpSignatureError("tag")
        if parameter(covered, "alg") != "ed25519":
            raise HttpSignatureError("alg_rejected")
        created = parameter(covered, "created")
        expires = parameter(covered, "expires")
        key_id = parameter(covered, "keyid")
        nonce = parameter(covered, "nonce")
        if isinstance(created, bool) or not isinstance(created, int):
            raise HttpSignatureError("malformed")
        if isinstance(expires, bool) or not isinstance(expires, int):
            raise HttpSignatureError("malformed")
        if created < 0 or expires < 0 or created > _UNIX_LIMIT or expires > _UNIX_LIMIT or created > expires:
            raise HttpSignatureError("malformed")
        if not isinstance(key_id, str) or _KEY_ID.fullmatch(key_id) is None:
            raise HttpSignatureError("malformed")
        if not isinstance(nonce, str) or not nonce:
            raise HttpSignatureError("nonce_missing")
        if len(nonce) > 200:
            raise HttpSignatureError("malformed")
        if not _covers(covered, "@authority") or not _covers(covered, "@path"):
            raise HttpSignatureError("missing_component")

    def _window(self, covered: InnerList, now: datetime) -> None:
        created = parameter(covered, "created")
        expires = parameter(covered, "expires")
        if isinstance(created, bool) or not isinstance(created, int):
            raise HttpSignatureError("malformed")
        if isinstance(expires, bool) or not isinstance(expires, int):
            raise HttpSignatureError("malformed")
        current = int(now.timestamp())
        if created > current + CREATED_SKEW_SECONDS:
            raise HttpSignatureError("not_yet_valid")
        if expires < current:
            raise HttpSignatureError("expired")

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


def parse_tap_keys(value: Any) -> tuple[dict[str, str], ...] | None:
    """Public TAP keys. ``None`` means the document is not usable.

    An absent value is an empty set. A private key, a non-Ed25519 algorithm,
    or a duplicate ``key_id`` refuses the whole set.
    """

    if value is None:
        return ()
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return ()
        try:
            value = json.loads(text)
        except json.JSONDecodeError:
            return None
    if isinstance(value, tuple):
        value = list(value)
    if not isinstance(value, list) or len(value) > _MAX_KEYS:
        return None
    records: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in value:
        parsed = _one_key(item)
        if parsed is None or parsed["key_id"] in seen:
            return None
        seen.add(parsed["key_id"])
        records.append(parsed)
    return tuple(records)


def _one_key(item: Any) -> dict[str, str] | None:
    if not isinstance(item, dict) or set(item) - _RECORD_FIELDS:
        return None
    if "d" in item or "private_key" in item:
        return None
    key_id = item.get("key_id")
    if not isinstance(key_id, str) or _KEY_ID.fullmatch(key_id) is None:
        return None
    if item.get("algorithm") != "ed25519":
        return None
    active = item.get("is_active")
    if active not in {"true", "false"}:
        return None
    raw = _raw_ed25519(item.get("public_key"))
    if raw is None:
        return None
    domain = _domain(item.get("agent_domain"))
    if domain is None:
        return None
    description = item.get("description", "")
    if "description" in item and (not isinstance(description, str) or len(description) > 200):
        return None
    return {
        "agent_domain": domain,
        "algorithm": "ed25519",
        "is_active": active,
        "key_id": key_id,
        "public_key": base64.b64encode(raw).decode("ascii"),
    }


def _raw_ed25519(value: Any) -> bytes | None:
    if not isinstance(value, str) or not value or len(value) > 200 or "-----" in value or "PRIVATE" in value:
        return None
    padding = "=" * (-len(value) % 4)
    try:
        raw = base64.urlsafe_b64decode(value + padding)
    except Exception:  # noqa: BLE001 — a bad encoding is not a public key
        return None
    if len(raw) != 32:
        return None
    return raw


def _domain(value: Any) -> str | None:
    if value is None:
        return ""
    if not isinstance(value, str) or len(value) > 200 or not value.isascii():
        return None
    if not value:
        return ""
    parsed = urlsplit(value)
    if parsed.scheme != "https" or parsed.username or parsed.password or parsed.fragment or not parsed.hostname:
        return None
    return value


def _index(value: Any) -> dict[str, _TapKey]:
    parsed = parse_tap_keys(value)
    if not parsed:
        return {}
    keys: dict[str, _TapKey] = {}
    for item in parsed:
        raw = _raw_ed25519(item["public_key"])
        if raw is None:
            continue
        keys[item["key_id"]] = _TapKey(
            key_id=item["key_id"],
            public=PublicKey(raw, "EdDSA"),
            active=item["is_active"] == "true",
            domain=item["agent_domain"],
        )
    return keys


def _covers(covered: InnerList, name: str) -> bool:
    for item in covered.items:
        if isinstance(item, Item) and item.value == name and not item.params:
            return True
    return False


def _stamp(now: datetime) -> str:
    return now.strftime("%Y-%m-%dT%H:%M:%SZ")
