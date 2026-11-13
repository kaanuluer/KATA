# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Pluggable evidence verifiers.

``jwt`` checks a compact JWT against a JWKS directory. ``synthetic`` is the
test verifier. Protocol adapters register another source later. None of them
returns a KATA decision.
"""

from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Mapping

from kata_service.evidence.jwks import (
    FetchFailed,
    JwksRejected,
    KeyCache,
    signing_key,
)
from kata_service.evidence.schema import (
    CLOCK_SKEW_SECONDS,
    empty_hash,
    evidence_object,
    payload_hash,
    sanitize_claims,
)
from kata_service.evidence.ssrf import DirectoryRejected
from kata_service.evidence.store import EvidenceStore

_ALLOWED_ALGS = frozenset({"EdDSA", "ES256"})
_SKEW = timedelta(seconds=CLOCK_SKEW_SECONDS)
Builder = Callable[..., Any]
_BUILDERS: dict[str, Builder] = {}


def register_verifier(source: str, builder: Builder) -> None:
    """Register a verifier factory. ``builder(store, **deps)`` returns a verifier."""

    _BUILDERS[source] = builder


def verifier_for(source: str, store: EvidenceStore, **deps: Any):
    builder = _BUILDERS.get(source)
    if builder is None:
        return UnsupportedVerifier(source)
    return builder(store, **deps)


def utc_seconds(now: datetime) -> datetime:
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    return now.astimezone(timezone.utc).replace(microsecond=0)


def _stamp(now: datetime) -> str:
    return utc_seconds(now).strftime("%Y-%m-%dT%H:%M:%SZ")


def _b64decode(segment: str) -> bytes | None:
    if not isinstance(segment, str) or any(ord(char) > 127 for char in segment):
        return None
    padding = "=" * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode(segment + padding)
    except Exception:  # noqa: BLE001 — a bad segment is a malformed token
        return None


def _text(value: Any, limit: int) -> str:
    if not isinstance(value, str) or len(value) > limit:
        return ""
    return value


def _numeric_date(value: Any) -> datetime | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if isinstance(value, float) and not value.is_integer():
        return None
    number = int(value)
    if number < 0 or number > 10_000_000_000:
        return None
    return datetime.fromtimestamp(number, timezone.utc).replace(microsecond=0)


class UnsupportedVerifier:
    source = "unknown"

    def __init__(self, source: str) -> None:
        self.source = source if isinstance(source, str) and 1 <= len(source) <= 64 else "unknown"

    def verify(self, material: Mapping[str, Any], *, now: datetime) -> dict[str, Any]:
        del material
        return evidence_object(
            source=self.source,
            verified_at=_stamp(now),
            result="unverifiable",
            reason="unsupported_verifier",
            payload_hash_hex=empty_hash(),
        )


class SyntheticVerifier:
    """Test verifier. ``accept`` stands in for a signature check. No network."""

    source = "synthetic"

    def __init__(self, store: EvidenceStore, **deps: Any) -> None:
        del deps
        self.store = store

    def verify(self, material: Mapping[str, Any], *, now: datetime) -> dict[str, Any]:
        moment = utc_seconds(now)
        stamp = _stamp(moment)
        if not isinstance(material, Mapping):
            return evidence_object(
                source=self.source,
                verified_at=stamp,
                result="invalid",
                reason="malformed",
                payload_hash_hex=empty_hash(),
            )
        raw_claims = material.get("claims") if isinstance(material.get("claims"), dict) else {}
        claims, sensitive = sanitize_claims(raw_claims)
        digest = payload_hash(json.dumps(claims, sort_keys=True, separators=(",", ":")).encode("utf-8"))
        issuer = _text(material.get("issuer"), 200)
        subject = _text(material.get("subject"), 200)
        key_id = _text(material.get("key_id"), 200)
        if sensitive:
            return evidence_object(
                source=self.source,
                issuer=issuer,
                subject=subject,
                verified_at=stamp,
                key_id=key_id,
                result="invalid",
                reason="sensitive_claim",
                payload_hash_hex=digest,
            )
        if material.get("accept") is not True:
            return evidence_object(
                source=self.source,
                issuer=issuer,
                subject=subject,
                claims=claims,
                verified_at=stamp,
                key_id=key_id,
                result="invalid",
                reason="signature",
                payload_hash_hex=digest,
            )
        nonce = material.get("nonce")
        if not isinstance(nonce, str) or not nonce or len(nonce) > 200 or not issuer or not subject or not key_id:
            return evidence_object(
                source=self.source,
                issuer=issuer,
                subject=subject,
                claims=claims,
                verified_at=stamp,
                key_id=key_id,
                result="invalid",
                reason="nonce_missing" if issuer and subject and key_id else "malformed",
                payload_hash_hex=digest,
            )
        ttl = material.get("ttl_seconds", 300)
        if isinstance(ttl, bool) or not isinstance(ttl, int) or ttl <= 0:
            ttl = 300
        fresh = self.store.consume_nonce(issuer, nonce, now=moment, expires_at=moment + timedelta(seconds=ttl))
        return evidence_object(
            source=self.source,
            issuer=issuer,
            subject=subject,
            claims=claims,
            verified_at=stamp,
            key_id=key_id,
            result="valid" if fresh else "invalid",
            reason="ok" if fresh else "replay",
            payload_hash_hex=digest,
        )


class JwtEvidenceVerifier:
    """Compact JWT (EdDSA or ES256) against an HTTPS JWKS directory."""

    source = "jwt"

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
        token = material.get("token") if isinstance(material, Mapping) else None
        if not isinstance(token, str):
            return self._invalid(stamp, "malformed", empty_hash())
        parts = token.split(".")
        if len(parts) != 3:
            return self._invalid(stamp, "malformed", empty_hash())
        if not parts[0].isascii() or not parts[1].isascii():
            return self._invalid(stamp, "malformed", empty_hash())
        header_bytes = _b64decode(parts[0])
        payload_bytes = _b64decode(parts[1])
        digest = payload_hash(payload_bytes or b"")
        if header_bytes is None or payload_bytes is None:
            return self._invalid(stamp, "malformed", digest)
        try:
            header = json.loads(header_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return self._invalid(stamp, "malformed", digest)
        if not isinstance(header, dict):
            return self._invalid(stamp, "malformed", digest)
        algorithm = header.get("alg")
        if not isinstance(algorithm, str) or algorithm not in _ALLOWED_ALGS:
            return self._invalid(stamp, "alg_rejected", digest)
        signature = _b64decode(parts[2]) if parts[2] else b""
        if signature is None:
            return self._invalid(stamp, "malformed", digest)
        try:
            payload = json.loads(payload_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return self._invalid(stamp, "malformed", digest)
        if not isinstance(payload, dict):
            return self._invalid(stamp, "malformed", digest)
        if "crit" in header:
            return self._invalid(stamp, "malformed", digest)
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            return self._invalid(stamp, "unknown_kid", digest, key_id="")
        timed = self._time_problem(payload, moment)
        if timed is not None:
            return self._from_payload(stamp, payload, digest, "invalid", timed, kid)
        claims, sensitive = sanitize_claims(payload)
        if sensitive:
            return self._invalid(stamp, "sensitive_claim", digest, key_id=kid)
        directory = material.get("directory")
        if not isinstance(directory, str):
            return self._from_payload(stamp, payload, digest, "unverifiable", "directory_url_rejected", kid)
        try:
            keys = self.cache.keys_for(directory, kid, moment)
        except DirectoryRejected:
            return self._from_payload(stamp, payload, digest, "unverifiable", "directory_url_rejected", kid)
        except JwksRejected:
            return self._from_payload(stamp, payload, digest, "unverifiable", "jwks_rejected", kid)
        except FetchFailed:
            return self._from_payload(stamp, payload, digest, "unverifiable", "jwks_fetch_failed", kid)
        chosen = next((item for item in keys if item["kid"] == kid), None)
        if chosen is None:
            return self._from_payload(stamp, payload, digest, "invalid", "unknown_kid", kid)
        if chosen["jwk"].get("alg") != algorithm:
            return self._from_payload(stamp, payload, digest, "invalid", "alg_mismatch", kid)
        key = signing_key(chosen["jwk"])
        if key is None or key.algorithm != algorithm:
            return self._from_payload(stamp, payload, digest, "invalid", "alg_mismatch", kid)
        try:
            signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
        except UnicodeEncodeError:
            return self._invalid(stamp, "malformed", digest, key_id=kid)
        if not signature or not key.verify(signing_input, signature):
            return self._from_payload(stamp, payload, digest, "invalid", "signature", kid)
        issuer = payload.get("iss")
        subject = payload.get("sub")
        if not isinstance(issuer, str) or not issuer or len(issuer) > 200:
            return self._from_payload(stamp, payload, digest, "invalid", "malformed", kid)
        if not isinstance(subject, str) or not subject or len(subject) > 200:
            return self._from_payload(stamp, payload, digest, "invalid", "malformed", kid)
        nonce = payload.get("jti")
        if not isinstance(nonce, str) or not nonce or len(nonce) > 200:
            return self._from_payload(stamp, payload, digest, "invalid", "nonce_missing", kid)
        exp = _numeric_date(payload.get("exp"))
        assert exp is not None  # _time_problem already required exp
        fresh = self.store.consume_nonce(issuer, nonce, now=moment, expires_at=exp + _SKEW)
        return evidence_object(
            source=self.source,
            issuer=issuer,
            subject=subject,
            claims=claims,
            verified_at=stamp,
            key_id=kid,
            result="valid" if fresh else "invalid",
            reason="ok" if fresh else "replay",
            payload_hash_hex=digest,
        )

    def _time_problem(self, payload: Mapping[str, Any], now: datetime) -> str | None:
        exp = _numeric_date(payload.get("exp"))
        if exp is None:
            return "malformed"
        if exp < now - _SKEW:
            return "expired"
        not_before = payload.get("nbf")
        if not_before is not None:
            moment = _numeric_date(not_before)
            if moment is None:
                return "malformed"
            if moment > now + _SKEW:
                return "not_yet_valid"
        issued = payload.get("iat")
        if issued is not None:
            moment = _numeric_date(issued)
            if moment is None:
                return "malformed"
            if moment > now + _SKEW:
                return "future_iat"
        return None

    def _from_payload(self, stamp, payload, digest, result, reason, kid) -> dict[str, Any]:
        claims, sensitive = sanitize_claims(payload)
        if sensitive:
            claims = {}
            if result == "valid":
                result, reason = "invalid", "sensitive_claim"
        issuer = payload.get("iss")
        subject = payload.get("sub")
        return evidence_object(
            source=self.source,
            issuer=issuer if isinstance(issuer, str) and len(issuer) <= 200 else "",
            subject=subject if isinstance(subject, str) and len(subject) <= 200 else "",
            claims=claims,
            verified_at=stamp,
            key_id=kid if isinstance(kid, str) and len(kid) <= 200 else "",
            result=result,
            reason=reason,
            payload_hash_hex=digest,
        )

    def _invalid(self, stamp: str, reason: str, digest: str, *, key_id: str = "") -> dict[str, Any]:
        result = "unverifiable" if reason in {"jwks_fetch_failed", "jwks_rejected", "directory_url_rejected"} else "invalid"
        return evidence_object(
            source=self.source,
            verified_at=stamp,
            key_id=key_id,
            result=result,
            reason=reason,
            payload_hash_hex=digest,
        )


def _synthetic_builder(store: EvidenceStore, **deps: Any) -> SyntheticVerifier:
    return SyntheticVerifier(store, **deps)


def _jwt_builder(store: EvidenceStore, **deps: Any) -> JwtEvidenceVerifier:
    return JwtEvidenceVerifier(store, **deps)


register_verifier("synthetic", _synthetic_builder)
register_verifier("jwt", _jwt_builder)
