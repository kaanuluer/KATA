# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Key providers for keyed HMAC and envelope encryption.

The proof of concept keeps one master key in the host environment
(``GAB_MASTER_KEY``) and stores each person's wrapped data key in the database,
apart from the ciphertext. Deleting that wrapped key is the shred. AWS KMS
implements the same wrap and unwrap calls and is not the default.

``EnvKeyProvider`` is for synthetic data and unit tests. It is not production
custody. Real customer personal data requires a KMS decision and the hosting
migration first.

HMAC outputs use ``v1:<kid>:<hex>``. The message is
``gab-hmac-v1 || NUL || purpose || NUL || value``. ``token_hash`` of high-entropy
secrets stays plain SHA-256 and does not use this module.

This module does not claim legal compliance or certification.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol

ENV_PROVIDER_NOTICE = (
    "NON-PRODUCTION and SYNTHETIC DATA ONLY. The master key is read from the process environment. "
    "This provider is refused when GAB_ENV is production. No flag overrides that refusal. "
    "Real customer personal data requires a KMS decision and the hosting migration first. "
    "If the host account that holds the environment is compromised, the master key is compromised too."
)

_HMAC_VERSION = "v1"
_KID_MAX = 64
_PURPOSES = frozenset({"identifier", "rate", "subject", "network", "kek", "ref"})
_HMAC_PREFIX = b"gab-hmac-v1"
_SUBJECT_PREFIX = b"gab-subject-v1"
_DEK_AAD = b"gab-dek-v1"
_SEAL_AAD = b"gab-seal-v1"
_HKDF_SALT = b"gab-hkdf-v1"
_HKDF_WRAP_INFO = b"gab-wrap-v1"
_HKDF_HMAC_INFO = b"gab-hmac-v1"
_HKDF_SUBJECT_INFO = b"gab-subject-ref-v1"
_DEK_CACHE_TTL_SECONDS = 300.0
_DEK_CACHE_MAX_ITEMS = 256
_NOT_HMAC = frozenset({"kek", "ref"})


class KeyCustodyError(Exception):
    """A key operation failed. The message names the setting, never the secret."""


class KmsClient(Protocol):
    """Host-neutral KMS calls. AWS KMS is one implementation."""

    def generate_data_key(self, *, key_id: str, encryption_context: dict[str, str]) -> tuple[bytes, bytes]:
        """Return ``(plaintext_dek, ciphertext_blob)``."""

    def encrypt(self, *, key_id: str, plaintext: bytes, encryption_context: dict[str, str]) -> bytes:
        """Wrap ``plaintext`` with the master key. Return the ciphertext blob."""

    def decrypt(self, *, key_id: str, ciphertext: bytes, encryption_context: dict[str, str]) -> bytes:
        """Unwrap a blob that was produced with the same encryption context."""


@dataclass(frozen=True)
class HmacToken:
    version: str
    kid: str
    digest_hex: str

    def encode(self) -> str:
        return f"{self.version}:{self.kid}:{self.digest_hex}"


@dataclass(frozen=True)
class KeyProviderInfo:
    provider: str
    custody: str
    production_custody: bool
    notice: str
    purposes: dict[str, dict[str, object]]


def hmac_message(purpose: str, value: str) -> bytes:
    _purpose(purpose)
    if purpose in _NOT_HMAC:
        raise KeyCustodyError(f"{purpose} is not an HMAC purpose")
    text = _value(value)
    return _HMAC_PREFIX + b"\x00" + purpose.encode("utf-8") + b"\x00" + text.encode("utf-8")


def hmac_encryption_context(purpose: str, kid: str) -> dict[str, str]:
    """Context that must be supplied when a KMS wraps or unwraps an HMAC key."""

    _purpose(purpose)
    _kid(kid)
    return {"gab": "hmac-key", "purpose": purpose, "kid": kid}


def opaque_subject(subject_id: str, key: bytes) -> str:
    """Keyed subject reference. The raw id is not recoverable from this value.

    An unkeyed hash of an email or a name can be guessed. The digest is
    HMAC-SHA256 over the label gab-subject-v1, a NUL, and the subject.
    The HMAC key is HKDF-SHA256 of the subject-reference secret. It is not
    the wrapping key. Rotating the wrapping key does not change this digest.
    """

    text = _subject(subject_id)
    if not isinstance(key, bytes) or len(key) != 32:
        raise KeyCustodyError("subject ref key must be 32 bytes")
    mac_key = _hkdf(key, _HKDF_SUBJECT_INFO)
    return hmac.new(mac_key, _SUBJECT_PREFIX + b"\x00" + text.encode("utf-8"), hashlib.sha256).hexdigest()


def dek_encryption_context(subject_id: str, key: bytes) -> dict[str, str]:
    return {"gab": "subject-dek", "purpose": "subject-dek", "subject_ref": opaque_subject(subject_id, key)}


@dataclass(frozen=True)
class KeyUsageEvent:
    """One key operation. No plaintext, no key bytes, and no raw subject id."""

    operation: str
    purpose: str
    kid: str
    subject_ref: str
    cache: str
    latency_ms: float


class _DekCache:
    """Process-local plaintext data keys.

    Entries expire after ``ttl_seconds`` (default 300). The map keeps at most
    ``max_items`` entries (default 256) and drops the soonest expiry first.
    ``forget`` drops every entry for one subject. Another process keeps its
    own copy until that copy's TTL elapses.
    """

    def __init__(
        self,
        *,
        ttl_seconds: float = _DEK_CACHE_TTL_SECONDS,
        max_items: int = _DEK_CACHE_MAX_ITEMS,
        clock=None,
    ) -> None:
        if ttl_seconds <= 0 or max_items < 1:
            raise KeyCustodyError("data key cache limits are invalid")
        self._ttl = float(ttl_seconds)
        self._max = int(max_items)
        self._clock = time.monotonic if clock is None else clock
        self._items: dict[tuple[str, bytes], tuple[bytes, float]] = {}
        self._lock = threading.Lock()

    def get(self, subject_ref: str, wrapped: bytes) -> bytes | None:
        key = self._key(subject_ref, wrapped)
        now = self._clock()
        with self._lock:
            item = self._items.get(key)
            if item is None:
                return None
            dek, expires = item
            if expires <= now:
                self._items.pop(key, None)
                return None
            return bytes(dek)

    def put(self, subject_ref: str, wrapped: bytes, dek: bytes) -> None:
        key = self._key(subject_ref, wrapped)
        now = self._clock()
        with self._lock:
            self._drop_expired(now)
            self._items[key] = (bytes(dek), now + self._ttl)
            self._shrink(keep=key)

    def drop(self, subject_ref: str, wrapped: bytes) -> None:
        with self._lock:
            self._items.pop(self._key(subject_ref, wrapped), None)

    def forget(self, subject_ref: str) -> None:
        with self._lock:
            for key in [item for item in self._items if item[0] == subject_ref]:
                self._items.pop(key, None)

    def _key(self, subject_ref: str, wrapped: bytes) -> tuple[str, bytes]:
        return (subject_ref, hashlib.sha256(wrapped).digest())

    def _drop_expired(self, now: float) -> None:
        stale = [key for key, (_dek, expires) in self._items.items() if expires <= now]
        for key in stale:
            self._items.pop(key, None)

    def _shrink(self, *, keep: tuple[str, bytes]) -> None:
        while len(self._items) > self._max:
            victims = [key for key in self._items if key != keep]
            if not victims:
                break
            oldest = min(victims, key=lambda item: self._items[item][1])
            self._items.pop(oldest, None)


class _UsageLog:
    def __init__(self) -> None:
        self._events: list[KeyUsageEvent] = []
        self._lock = threading.Lock()

    def add(self, event: KeyUsageEvent) -> None:
        with self._lock:
            self._events.append(event)
            if len(self._events) > 200:
                del self._events[: len(self._events) - 200]

    def events(self) -> list[KeyUsageEvent]:
        with self._lock:
            return list(self._events)


def _record(
    log: _UsageLog,
    operation: str,
    started: float,
    *,
    purpose: str = "",
    kid: str = "",
    subject_ref: str = "",
    cache: str = "none",
) -> None:
    ref = subject_ref
    log.add(
        KeyUsageEvent(
            operation,
            purpose,
            kid,
            ref,
            cache,
            (time.perf_counter() - started) * 1000,
        )
    )


def parse_hmac_token(token: str) -> HmacToken | None:
    parts = token.split(":")
    if len(parts) != 3:
        return None
    version, kid, digest = parts
    if version != _HMAC_VERSION:
        return None
    try:
        _kid(kid)
    except KeyCustodyError:
        return None
    if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
        return None
    return HmacToken(version, kid, digest)


class EnvKeyProvider:
    """Master key and HMAC keys read from the process environment.

    This is the proof-of-concept provider. It is for synthetic data and tests.
    ``production_custody`` is always false. ``GAB_MASTER_KEY`` is the wrapping
    key when it is set. Its id is ``master_key_id`` (``GAB_MASTER_KEY_ID``,
    default ``master``). Subject references use purpose ``ref`` or
    ``subject_key``. They do not use the wrapping key. A ring entry with
    purpose ``kek`` is the fallback for tests that do not set a master key.
    """

    provider = "env"
    custody = "non-production-env"

    def __init__(
        self,
        ring: dict[str, dict[str, object]],
        active: dict[str, str] | None = None,
        *,
        active_strict: bool = True,
        master_key: bytes | None = None,
        master_key_id: str | None = None,
        subject_key: bytes | None = None,
        subject_key_id: str | None = None,
    ) -> None:
        self._dek_cache = _DekCache()
        self._usage = _UsageLog()
        self._keys: dict[str, bytes] = {}
        self._purposes: dict[str, list[str]] = {}
        self._active: dict[str, str] = {}
        cleaned = _normalize_ring(ring)
        for kid, record in cleaned.items():
            self._keys[kid] = record["secret"]
            for purpose in record["purposes"]:
                self._purposes.setdefault(purpose, []).append(kid)
                if record["active"] and purpose not in self._active:
                    self._active[purpose] = kid
        if master_key is not None:
            self._install(master_key_id or "master", master_key, "kek")
        if subject_key is not None:
            self._install(subject_key_id or "subject-ref", subject_key, "ref")
        for purpose, kids in self._purposes.items():
            self._active.setdefault(purpose, kids[-1])
        _apply_active_map(
            self._active,
            {purpose: list(kids) for purpose, kids in self._purposes.items()},
            active,
            strict=active_strict,
        )
        if master_key is not None:
            self._active["kek"] = _kid(master_key_id or "master")
        if subject_key is not None:
            self._active["ref"] = _kid(subject_key_id or "subject-ref")
        if not self._keys:
            raise KeyCustodyError("the env key ring is empty")

    @property
    def production_custody(self) -> bool:
        return False

    def notice(self) -> str:
        return ENV_PROVIDER_NOTICE

    def info(self) -> KeyProviderInfo:
        purposes: dict[str, dict[str, object]] = {}
        for purpose, kids in sorted(self._purposes.items()):
            purposes[purpose] = {"active_kid": self._active.get(purpose), "kids": list(kids)}
        return KeyProviderInfo(self.provider, self.custody, False, ENV_PROVIDER_NOTICE, purposes)

    def __repr__(self) -> str:
        kids = ",".join(sorted(self._keys))
        return f"EnvKeyProvider(NON-PRODUCTION, kids={kids})"

    def active_kid(self, purpose: str) -> str:
        _purpose(purpose)
        kid = self._active.get(purpose)
        if kid is None:
            raise KeyCustodyError(f"no HMAC key is configured for purpose {purpose}")
        return kid

    def kids_for(self, purpose: str) -> list[str]:
        _purpose(purpose)
        return list(self._purposes.get(purpose, []))

    def usage(self) -> list[KeyUsageEvent]:
        return self._usage.events()

    def subject_ref(self, subject_id: str) -> str:
        return opaque_subject(subject_id, self._subject_key_bytes())

    def subject_refs(self, subject_id: str) -> list[str]:
        """Active subject reference first, then references under previous ref keys."""

        return [opaque_subject(subject_id, key) for key in self._subject_ikms()]

    def previous_subject_keys(self) -> tuple[bytes, ...]:
        return tuple(self._subject_ikms()[1:])

    def forget_dek(self, subject_id: str) -> None:
        for ref in self.subject_refs(subject_id):
            self._dek_cache.forget(ref)

    def drop_wrapped(self, subject_id: str, wrapped: bytes) -> None:
        for ref in self.subject_refs(subject_id):
            self._dek_cache.drop(ref, wrapped)

    def hmac(self, value: str, *, purpose: str) -> HmacToken:
        started = time.perf_counter()
        token = self._hmac_kid(self.active_kid(purpose), value, purpose)
        _record(self._usage, "hmac", started, purpose=purpose, kid=token.kid)
        return token

    def hmac_tokens(self, value: str, *, purpose: str) -> list[HmacToken]:
        active = self.active_kid(purpose)
        order = [active] + [kid for kid in self.kids_for(purpose) if kid != active]
        return [self._hmac_kid(kid, value, purpose) for kid in order]

    def verify(self, token: str, value: str, *, purpose: str) -> bool:
        parsed = parse_hmac_token(token)
        if parsed is None or parsed.kid not in self._purposes.get(purpose, []):
            hmac.compare_digest("0" * 64, "0" * 64)
            return False
        expected = self._hmac_kid(parsed.kid, value, purpose).digest_hex
        return hmac.compare_digest(expected, parsed.digest_hex)

    def issue_dek(self, subject_id: str) -> tuple[bytes, bytes]:
        """Return ``(plaintext_dek, wrapped_blob)``. The caller wipes the plaintext."""

        started = time.perf_counter()
        ref = self.subject_ref(subject_id)
        kek, kek_id = self._kek()
        dek = os.urandom(32)
        wrapped = _wrap_with_aes(kek, kek_id, dek, _dek_aad(ref))
        self._dek_cache.put(ref, wrapped, dek)
        _record(self._usage, "issue_dek", started, purpose="kek", kid=kek_id, subject_ref=ref)
        return dek, wrapped

    def unwrap_dek(self, subject_id: str, wrapped: bytes) -> bytes:
        started = time.perf_counter()
        refs = self.subject_refs(subject_id)
        for ref in refs:
            cached = self._dek_cache.get(ref, wrapped)
            if cached is not None:
                _record(self._usage, "unwrap_dek", started, purpose="kek", subject_ref=ref, cache="hit")
                return cached
        kek_id, nonce, ciphertext = _split_wrapped(wrapped)
        kek = self._keys.get(kek_id)
        if kek is None or kek_id not in self._purposes.get("kek", []):
            raise KeyCustodyError("wrapped data key does not match a local kek")
        plain = None
        matched = None
        for ref in refs:
            try:
                plain = _open_aes(_wrap_key(kek), nonce, ciphertext, _dek_aad(ref))
            except KeyCustodyError:
                continue
            matched = ref
            break
        if plain is None or matched is None:
            raise KeyCustodyError("ciphertext did not open")
        self._dek_cache.put(matched, wrapped, plain)
        _record(self._usage, "unwrap_dek", started, purpose="kek", kid=kek_id, subject_ref=matched, cache="miss")
        return plain

    def seal(self, plaintext: bytes, *, subject_id: str) -> str:
        started = time.perf_counter()
        ref = self.subject_ref(subject_id)
        dek, wrapped = self.issue_dek(subject_id)
        try:
            encoded = _encode_seal(ref, dek, plaintext, wrapped)
        finally:
            _wipe(dek)
        _record(self._usage, "seal", started, subject_ref=ref)
        return encoded

    def unseal(self, encoded: str, *, subject_id: str) -> bytes:
        started = time.perf_counter()
        subject, dek_wrapped, nonce, ciphertext = _decode_seal(encoded)
        if not _subject_ref_match(self, subject_id, subject):
            raise KeyCustodyError("ciphertext did not open")
        dek = self.unwrap_dek(subject_id, dek_wrapped)
        try:
            opened = _open_aes(dek, nonce, ciphertext, _seal_aad(subject))
        finally:
            _wipe(dek)
        _record(self._usage, "unseal", started, subject_ref=subject)
        return opened

    def _subject_ikms(self) -> list[bytes]:
        active = self._active.get("ref")
        kids = list(self._purposes.get("ref", []))
        if active is None or active not in self._keys:
            raise KeyCustodyError("no subject ref key is configured")
        ordered = [active] + [kid for kid in kids if kid != active]
        return [self._keys[kid] for kid in ordered]

    def _subject_key_bytes(self) -> bytes:
        return self._subject_ikms()[0]

    def _install(self, kid: str, secret: bytes, purpose: str) -> None:
        cleaned = _kid(kid)
        if not isinstance(secret, bytes) or len(secret) != 32:
            raise KeyCustodyError("key material must be 32 bytes")
        current = self._keys.get(cleaned)
        if current is not None and not hmac.compare_digest(current, secret):
            raise KeyCustodyError(f"key id {cleaned} already has different key material")
        self._keys[cleaned] = bytes(secret)
        kids = self._purposes.setdefault(purpose, [])
        if cleaned not in kids:
            kids.append(cleaned)

    def _hmac_kid(self, kid: str, value: str, purpose: str) -> HmacToken:
        if purpose in _NOT_HMAC or kid not in self._purposes.get(purpose, []):
            raise KeyCustodyError(f"no HMAC key is configured for purpose {purpose}")
        digest = hmac.new(_hmac_key(self._keys[kid], purpose), hmac_message(purpose, value), hashlib.sha256).hexdigest()
        return HmacToken(_HMAC_VERSION, kid, digest)

    def _kek(self) -> tuple[bytes, str]:
        kid = self._active.get("kek")
        if kid is None:
            raise KeyCustodyError("no kek is configured for envelope encryption")
        return self._keys[kid], kid


class AwsKmsEnvelopeProvider:
    """AWS KMS envelope provider.

    The master key stays in KMS. This process sees plaintext data keys only
    after KMS unwraps them. HMAC keys are data keys wrapped by that master
    key (``GAB_KMS_WRAPPED_HMAC_KEYS``). Per-subject DEKs come from
    ``GenerateDataKey`` and are wrapped by the same master key.
    """

    provider = "aws-kms"
    custody = "aws-kms-envelope"

    def __init__(
        self,
        *,
        key_id: str,
        region: str,
        wrapped_hmac: dict[str, list[dict[str, object]]] | None = None,
        client: KmsClient | None = None,
        active: dict[str, str] | None = None,
        active_strict: bool = True,
        subject_key: bytes | None = None,
    ) -> None:
        self.key_id = _kms_key_id(key_id)
        self.region = _region(region)
        if subject_key is None:
            self._subject_key = None
        elif isinstance(subject_key, bytes) and len(subject_key) == 32:
            self._subject_key = bytes(subject_key)
        else:
            raise KeyCustodyError("subject ref key must be 32 bytes")
        self._client = client
        self._lock = threading.Lock()
        self._cache: dict[str, bytes] = {}
        self._dek_cache = _DekCache()
        self._usage = _UsageLog()
        self._wrapped: dict[str, list[dict[str, str]]] = {}
        self._active: dict[str, str] = {}
        for purpose, records in (wrapped_hmac or {}).items():
            _purpose(purpose)
            if purpose in _NOT_HMAC:
                raise KeyCustodyError(f"{purpose} is not an HMAC purpose")
            normalized = []
            for record in records:
                kid = _kid(str(record["kid"]))
                blob = str(record["wrapped"])
                if not blob or len(blob) > 20000:
                    raise KeyCustodyError("a wrapped HMAC key blob is missing or too large")
                normalized.append({"kid": kid, "wrapped": blob})
                if record.get("active") and purpose not in self._active:
                    self._active[purpose] = kid
            if not normalized:
                continue
            self._wrapped[purpose] = normalized
            self._active.setdefault(purpose, normalized[-1]["kid"])
        _apply_active_map(
            self._active,
            {purpose: [item["kid"] for item in records] for purpose, records in self._wrapped.items()},
            active,
            strict=active_strict,
        )

    @property
    def production_custody(self) -> bool:
        return True

    def notice(self) -> str:
        return (
            "AWS KMS is available when GAB_KEY_PROVIDER=aws-kms. It is not the proof-of-concept default. "
            "The master key stays in KMS and wraps per-subject data keys."
        )

    def info(self) -> KeyProviderInfo:
        purposes = {
            purpose: {"active_kid": self._active.get(purpose), "kids": [item["kid"] for item in records]}
            for purpose, records in sorted(self._wrapped.items())
        }
        return KeyProviderInfo(self.provider, self.custody, True, self.notice(), purposes)

    def __repr__(self) -> str:
        return f"AwsKmsEnvelopeProvider(region={self.region}, key_id={self.key_id})"

    def active_kid(self, purpose: str) -> str:
        _purpose(purpose)
        kid = self._active.get(purpose)
        if kid is None:
            raise KeyCustodyError(f"no HMAC key is configured for purpose {purpose}")
        return kid

    def kids_for(self, purpose: str) -> list[str]:
        return [item["kid"] for item in self._wrapped.get(purpose, [])]

    def usage(self) -> list[KeyUsageEvent]:
        return self._usage.events()

    def subject_ref(self, subject_id: str) -> str:
        return opaque_subject(subject_id, self._subject_key_bytes())

    def subject_refs(self, subject_id: str) -> list[str]:
        return [self.subject_ref(subject_id)]

    def previous_subject_keys(self) -> tuple[bytes, ...]:
        return ()

    def forget_dek(self, subject_id: str) -> None:
        self._dek_cache.forget(self.subject_ref(subject_id))

    def drop_wrapped(self, subject_id: str, wrapped: bytes) -> None:
        self._dek_cache.drop(self.subject_ref(subject_id), wrapped)

    def hmac(self, value: str, *, purpose: str) -> HmacToken:
        started = time.perf_counter()
        token = self._hmac_kid(self.active_kid(purpose), value, purpose)
        _record(self._usage, "hmac", started, purpose=purpose, kid=token.kid)
        return token

    def hmac_tokens(self, value: str, *, purpose: str) -> list[HmacToken]:
        active = self.active_kid(purpose)
        order = [active] + [kid for kid in self.kids_for(purpose) if kid != active]
        return [self._hmac_kid(kid, value, purpose) for kid in order]

    def verify(self, token: str, value: str, *, purpose: str) -> bool:
        parsed = parse_hmac_token(token)
        if parsed is None or parsed.kid not in self.kids_for(purpose):
            hmac.compare_digest("0" * 64, "0" * 64)
            return False
        expected = self._hmac_kid(parsed.kid, value, purpose).digest_hex
        return hmac.compare_digest(expected, parsed.digest_hex)

    def issue_dek(self, subject_id: str) -> tuple[bytes, bytes]:
        started = time.perf_counter()
        ref = self.subject_ref(subject_id)
        plaintext, blob = _kms_call(
            lambda: self._kms().generate_data_key(
                key_id=self.key_id,
                encryption_context=dek_encryption_context(subject_id, self._subject_key_bytes()),
            )
        )
        if len(plaintext) != 32:
            _wipe(plaintext)
            raise KeyCustodyError("KMS data key was not 32 bytes")
        wrapped = _pack_kms_dek(self.key_id, blob)
        self._dek_cache.put(ref, wrapped, plaintext)
        _record(self._usage, "issue_dek", started, purpose="kek", kid=self.key_id, subject_ref=ref)
        return plaintext, wrapped

    def unwrap_dek(self, subject_id: str, wrapped: bytes) -> bytes:
        started = time.perf_counter()
        ref = self.subject_ref(subject_id)
        cached = self._dek_cache.get(ref, wrapped)
        if cached is not None:
            _record(self._usage, "unwrap_dek", started, purpose="kek", subject_ref=ref, cache="hit")
            return cached
        key_id, blob = _unpack_kms_dek(wrapped)
        if key_id != self.key_id:
            raise KeyCustodyError("wrapped data key was not produced for this master key")
        plaintext = _kms_call(
            lambda: self._kms().decrypt(
                key_id=self.key_id,
                ciphertext=blob,
                encryption_context=dek_encryption_context(subject_id, self._subject_key_bytes()),
            )
        )
        if len(plaintext) != 32:
            _wipe(plaintext)
            raise KeyCustodyError("KMS data key was not 32 bytes")
        self._dek_cache.put(ref, wrapped, plaintext)
        _record(self._usage, "unwrap_dek", started, purpose="kek", kid=key_id, subject_ref=ref, cache="miss")
        return plaintext

    def seal(self, plaintext: bytes, *, subject_id: str) -> str:
        started = time.perf_counter()
        ref = self.subject_ref(subject_id)
        dek, wrapped = self.issue_dek(subject_id)
        try:
            encoded = _encode_seal(ref, dek, plaintext, wrapped)
        finally:
            _wipe(dek)
        _record(self._usage, "seal", started, subject_ref=ref)
        return encoded

    def unseal(self, encoded: str, *, subject_id: str) -> bytes:
        started = time.perf_counter()
        subject, dek_wrapped, nonce, ciphertext = _decode_seal(encoded)
        if not _subject_ref_match(self, subject_id, subject):
            raise KeyCustodyError("ciphertext did not open")
        dek = self.unwrap_dek(subject_id, dek_wrapped)
        try:
            opened = _open_aes(dek, nonce, ciphertext, _seal_aad(subject))
        finally:
            _wipe(dek)
        _record(self._usage, "unseal", started, subject_ref=subject)
        return opened

    def _subject_key_bytes(self) -> bytes:
        if self._subject_key is None:
            raise KeyCustodyError("aws-kms needs a 32-byte subject ref key")
        return self._subject_key

    def _hmac_kid(self, kid: str, value: str, purpose: str) -> HmacToken:
        secret = _hmac_key(self._hmac_secret(purpose, kid), purpose)
        digest = hmac.new(secret, hmac_message(purpose, value), hashlib.sha256).hexdigest()
        return HmacToken(_HMAC_VERSION, kid, digest)

    def _hmac_secret(self, purpose: str, kid: str) -> bytes:
        cache_id = purpose + "\x00" + kid
        with self._lock:
            cached = self._cache.get(cache_id)
        if cached is not None:
            return cached
        record = next((item for item in self._wrapped.get(purpose, []) if item["kid"] == kid), None)
        if record is None:
            raise KeyCustodyError(f"no HMAC key is configured for purpose {purpose}")
        try:
            blob = _b64decode(record["wrapped"])
        except ValueError as exc:
            raise KeyCustodyError("a wrapped HMAC key is not valid base64") from exc
        plaintext = _kms_call(
            lambda: self._kms().decrypt(
                key_id=self.key_id,
                ciphertext=blob,
                encryption_context=hmac_encryption_context(purpose, kid),
            )
        )
        if len(plaintext) != 32:
            raise KeyCustodyError("unwrapped HMAC key was not 32 bytes")
        with self._lock:
            self._cache[cache_id] = plaintext
        return plaintext

    def _kms(self) -> KmsClient:
        if self._client is not None:
            return self._client
        self._client = Boto3KmsClient(self.region)
        return self._client


class Boto3KmsClient:
    """Lazy AWS KMS adapter. boto3 is imported on first use, not at process start."""

    def __init__(self, region: str) -> None:
        self._region = region
        self._client = None

    def _boto(self):
        if self._client is None:
            _require_web_identity()
            try:
                import boto3
            except ImportError as exc:
                raise KeyCustodyError("aws-kms needs the optional boto3 extra installed") from exc
            self._client = boto3.client("kms", region_name=self._region)
        return self._client

    def generate_data_key(self, *, key_id: str, encryption_context: dict[str, str]) -> tuple[bytes, bytes]:
        response = _kms_call(
            lambda: self._boto().generate_data_key(
                KeyId=key_id,
                KeySpec="AES_256",
                EncryptionContext=encryption_context,
            )
        )
        plain = response.get("Plaintext") if isinstance(response, dict) else None
        blob = response.get("CiphertextBlob") if isinstance(response, dict) else None
        if not isinstance(plain, (bytes, bytearray)) or not isinstance(blob, (bytes, bytearray)):
            raise KeyCustodyError("KMS request failed")
        return bytes(plain), bytes(blob)

    def encrypt(self, *, key_id: str, plaintext: bytes, encryption_context: dict[str, str]) -> bytes:
        response = _kms_call(
            lambda: self._boto().encrypt(KeyId=key_id, Plaintext=plaintext, EncryptionContext=encryption_context)
        )
        blob = response.get("CiphertextBlob") if isinstance(response, dict) else None
        if not isinstance(blob, (bytes, bytearray)):
            raise KeyCustodyError("KMS request failed")
        return bytes(blob)

    def decrypt(self, *, key_id: str, ciphertext: bytes, encryption_context: dict[str, str]) -> bytes:
        response = _kms_call(
            lambda: self._boto().decrypt(
                CiphertextBlob=ciphertext,
                EncryptionContext=encryption_context,
                KeyId=key_id,
            )
        )
        plain = response.get("Plaintext") if isinstance(response, dict) else None
        if not isinstance(plain, (bytes, bytearray)):
            raise KeyCustodyError("KMS did not unwrap the data key")
        return bytes(plain)


class InProcessDekStore:
    """Process-local wrapped-DEK map for tests.

    Not durable. The proof-of-concept store is ``DatabaseDekStore``.
    ``previous_keys`` are older subject-reference secrets. ``get`` and
    ``destroy`` try those digests so a rotated ref key can still find the row.
    ``put`` writes only the active digest.
    """

    def __init__(self, subject_key: bytes, *, previous_keys: tuple[bytes, ...] = ()) -> None:
        self._ring = _SubjectRefRing(subject_key, previous_keys)
        self._items: dict[str, bytes] = {}
        self._lock = threading.Lock()

    def subject_ref(self, subject_id: str) -> str:
        return self._ring.subject_ref(subject_id)

    def put(self, subject_id: str, wrapped: bytes) -> bytes:
        """Insert the wrapped key when this subject has none. Never replace it."""

        ref = self.subject_ref(subject_id)
        with self._lock:
            current = self._items.get(ref)
            if current is None:
                current = bytes(wrapped)
                self._items[ref] = current
            return bytes(current)

    def get(self, subject_id: str) -> bytes | None:
        with self._lock:
            for ref in self._ring.refs(subject_id):
                item = self._items.get(ref)
                if item is not None:
                    return bytes(item)
            return None

    def destroy(self, subject_id: str) -> bool:
        removed = False
        with self._lock:
            for ref in self._ring.refs(subject_id):
                if self._items.pop(ref, None) is not None:
                    removed = True
        return removed


class DatabaseDekStore:
    """Wrapped per-person data keys in ``gab_subject_deks``.

    The table holds the wrapped key only. Ciphertext stays in its own column.
    ``put`` inserts the first key and leaves that row in place. ``destroy`` is
    the only delete. A database backup taken before that delete still contains
    the wrapped key. ``subject_ref`` is a keyed HMAC.
    """

    def __init__(self, connect, *, subject_key: bytes, previous_keys: tuple[bytes, ...] = ()) -> None:
        self._connect = connect
        self._ring = _SubjectRefRing(subject_key, previous_keys)

    def subject_ref(self, subject_id: str) -> str:
        return self._ring.subject_ref(subject_id)

    def put(self, subject_id: str, wrapped: bytes) -> bytes:
        """Insert the wrapped key if absent, then return the stored key.

        ``ON CONFLICT DO NOTHING`` plus a read-back keeps one key when two
        callers insert at the same time. A later put does not replace it.
        Only ``destroy`` deletes a row.
        """

        ref = self.subject_ref(subject_id)
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO gab_subject_deks (subject_ref, wrapped_dek, created_at)
                VALUES (%s, %s, %s)
                ON CONFLICT (subject_ref) DO NOTHING
                """,
                (ref, _b64encode(wrapped), stamp),
            )
            row = conn.execute(
                "SELECT wrapped_dek FROM gab_subject_deks WHERE subject_ref = %s",
                (ref,),
            ).fetchone()
        return _stored_wrapped(row)

    def get(self, subject_id: str) -> bytes | None:
        with self._connect() as conn:
            for ref in self._ring.refs(subject_id):
                row = conn.execute(
                    "SELECT wrapped_dek FROM gab_subject_deks WHERE subject_ref = %s",
                    (ref,),
                ).fetchone()
                if row is not None:
                    return _stored_wrapped(row)
        return None

    def destroy(self, subject_id: str) -> bool:
        removed = False
        with self._connect() as conn:
            for ref in self._ring.refs(subject_id):
                cursor = conn.execute("DELETE FROM gab_subject_deks WHERE subject_ref = %s", (ref,))
                removed = removed or cursor.rowcount > 0
        return removed


def seal_detached(provider, plaintext: bytes, *, subject_id: str, store) -> tuple[str, bytes]:
    """Encrypt with the subject's stored data key, creating it on first use.

    A second call reuses that key, so the first ciphertext stays readable.
    Only ``shred_subject`` deletes the stored key.

    The return value includes the wrapped data key. A caller who stores that
    wrapped value can still open the ciphertext after shred. Shred deletes
    the store row and this process's cache. It does not erase a copy the
    caller kept.
    """

    ref = provider.subject_ref(subject_id)
    if not hmac.compare_digest(ref, store.subject_ref(subject_id)):
        raise KeyCustodyError("data key store subject ref does not match the provider")
    wrapped = store.get(subject_id)
    if wrapped is None:
        fresh_plain, fresh = provider.issue_dek(subject_id)
        _wipe(fresh_plain)
        stored = store.put(subject_id, fresh)
        if not _same_bytes(stored, fresh):
            provider.drop_wrapped(subject_id, fresh)
        wrapped = stored
    dek = provider.unwrap_dek(subject_id, wrapped)
    try:
        nonce = os.urandom(12)
        ciphertext = _AESGCM(dek).encrypt(nonce, plaintext, _seal_aad(ref))
    finally:
        _wipe(dek)
    encoded = ".".join(
        [
            "gabseal1",
            "detached",
            _b64encode(ref.encode("utf-8")),
            _b64encode(nonce),
            _b64encode(ciphertext),
        ]
    )
    return encoded, wrapped


def open_detached(provider, encoded: str, wrapped: bytes, *, subject_id: str) -> bytes:
    """Open a detached ciphertext with a wrapped data key the caller still holds.

    This does not read the store. A wrapped blob kept from ``seal_detached``
    still opens after ``shred_subject``. Use ``open_stored`` for the path
    that fails once the store row is gone.
    """

    if not isinstance(wrapped, (bytes, bytearray)) or not wrapped:
        raise KeyCustodyError("ciphertext did not open")
    parts = encoded.split(".")
    if len(parts) != 5 or parts[0] != "gabseal1" or parts[1] != "detached":
        raise KeyCustodyError("ciphertext did not open")
    try:
        subject = _b64decode(parts[2]).decode("utf-8")
        nonce = _b64decode(parts[3])
        ciphertext = _b64decode(parts[4])
    except (ValueError, UnicodeError) as exc:
        raise KeyCustodyError("ciphertext did not open") from exc
    if not _subject_ref_match(provider, subject_id, subject):
        raise KeyCustodyError("ciphertext did not open")
    dek = provider.unwrap_dek(subject_id, bytes(wrapped))
    try:
        return _open_aes(dek, nonce, ciphertext, _seal_aad(subject))
    finally:
        _wipe(dek)


def open_stored(provider, encoded: str, *, subject_id: str, store) -> bytes:
    """Open a detached ciphertext by reading the wrapped key from the store.

    After ``shred_subject`` the store has no row, and this raises.
    """

    wrapped = store.get(subject_id)
    if not isinstance(wrapped, (bytes, bytearray)) or not wrapped:
        raise KeyCustodyError("ciphertext did not open")
    return open_detached(provider, encoded, bytes(wrapped), subject_id=subject_id)


def shred_subject(provider, store, subject_id: str) -> bool:
    """Drop the cached data key and remove the wrapped key from the live store in this process.

    A backup or a restore can bring the wrapped key back. An embedded seal
    string cannot be shredded. Another process may hold the data key for up
    to 300 seconds.
    """

    removed = bool(store.destroy(subject_id))
    provider.forget_dek(subject_id)
    return removed


def database_dek_store(provider, connect):
    """Build a live-database store for wrapped per-person data keys."""

    previous = provider.previous_subject_keys() if hasattr(provider, "previous_subject_keys") else ()
    return DatabaseDekStore(connect, subject_key=provider._subject_key_bytes(), previous_keys=tuple(previous))


def provider_from_env(env: dict[str, str], *, deployment_env: str) -> EnvKeyProvider | AwsKmsEnvelopeProvider | None:
    """Build the configured provider.

    Unset ``GAB_KEY_PROVIDER`` with no ``GAB_MASTER_KEY`` returns None.
    A master key with no provider name selects ``env``, the proof-of-concept
    default, except when ``deployment_env`` is production. ``aws-kms`` is
    selected only when named. Production refuses ``env``. ``GAB_SYNTHETIC_DATA``
    and ``GAB_ALLOW_ENV_KEYS`` do not override that refusal.
    """

    name = _blank(env.get("GAB_KEY_PROVIDER"))
    master = _parse_master(env.get("GAB_MASTER_KEY"))
    if name is None and master is None:
        return None
    folded = "env" if name is None else name.lower().replace("_", "-")
    if folded == "env":
        _refuse_env_in_production(deployment_env)
        ring = _parse_hmac_keys(env.get("GAB_HMAC_KEYS"), allow_empty=master is not None)
        active, strict = _parse_active(env.get("GAB_HMAC_ACTIVE_KID"))
        return EnvKeyProvider(
            ring,
            active,
            active_strict=strict,
            master_key=master,
            master_key_id=_blank(env.get("GAB_MASTER_KEY_ID")),
            subject_key=_parse_subject_key(env.get("GAB_SUBJECT_REF_KEY")),
            subject_key_id=_blank(env.get("GAB_SUBJECT_REF_KID")),
        )
    if folded == "aws-kms":
        key_id = _blank(env.get("GAB_KMS_KEY_ID"))
        region = _blank(env.get("GAB_KMS_REGION"))
        if key_id is None or region is None:
            raise KeyCustodyError("aws-kms needs GAB_KMS_KEY_ID and GAB_KMS_REGION")
        wrapped = _parse_wrapped_hmac(env.get("GAB_KMS_WRAPPED_HMAC_KEYS"))
        active, strict = _parse_active(env.get("GAB_HMAC_ACTIVE_KID"))
        return AwsKmsEnvelopeProvider(
            key_id=key_id,
            region=region,
            wrapped_hmac=wrapped,
            active=active,
            active_strict=strict,
            subject_key=_parse_subject_key(env.get("GAB_SUBJECT_REF_KEY")),
        )
    raise KeyCustodyError("GAB_KEY_PROVIDER must be env or aws-kms")


def _refuse_env_in_production(deployment_env: str) -> None:
    if deployment_env != "production":
        return
    raise KeyCustodyError(
        "GAB_KEY_PROVIDER=env is refused when GAB_ENV is production. "
        "GAB_SYNTHETIC_DATA and GAB_ALLOW_ENV_KEYS do not override this."
    )


def _require_web_identity() -> None:
    """Reject static AWS keys. The future path is a short-lived OIDC role."""

    static = [
        name
        for name in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN")
        if _blank(os.environ.get(name))
    ]
    if static:
        names = ", ".join(static)
        raise KeyCustodyError(
            f"aws-kms refuses long-lived credentials in {names}. "
            "Set AWS_ROLE_ARN and AWS_WEB_IDENTITY_TOKEN_FILE for Vercel OIDC. "
            "Do not set AWS_ACCESS_KEY_ID or AWS_SECRET_ACCESS_KEY."
        )
    role = _blank(os.environ.get("AWS_ROLE_ARN"))
    token_file = _blank(os.environ.get("AWS_WEB_IDENTITY_TOKEN_FILE"))
    vercel_token = os.environ.get("VERCEL_OIDC_TOKEN")
    if role and token_file is None and vercel_token:
        token_file = _write_oidc_token(vercel_token)
        os.environ["AWS_WEB_IDENTITY_TOKEN_FILE"] = token_file
    if role is None or token_file is None:
        raise KeyCustodyError(
            "aws-kms needs AWS_ROLE_ARN and AWS_WEB_IDENTITY_TOKEN_FILE. "
            "VERCEL_OIDC_TOKEN can supply the file. Static AWS keys are not accepted."
        )


def _write_oidc_token(token: str) -> str:
    import tempfile

    directory = tempfile.mkdtemp(prefix="gab-oidc-")
    path = os.path.join(directory, "token")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(token)
    return path


def _parse_master(raw: str | None) -> bytes | None:
    text = _blank(raw)
    if text is None:
        return None
    try:
        decoded = _b64decode(text)
    except ValueError as exc:
        raise KeyCustodyError("GAB_MASTER_KEY is not valid base64") from exc
    if len(decoded) != 32:
        raise KeyCustodyError("GAB_MASTER_KEY must decode to 32 bytes")
    return decoded


def _parse_hmac_keys(raw: str | None, *, allow_empty: bool = False) -> dict[str, dict[str, object]]:
    text = _blank(raw)
    if text is None:
        if allow_empty:
            return {}
        raise KeyCustodyError("GAB_HMAC_KEYS is required for the env provider")
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        raise KeyCustodyError("GAB_HMAC_KEYS is not valid JSON") from exc
    if not isinstance(parsed, dict) or (not parsed and not allow_empty):
        raise KeyCustodyError("GAB_HMAC_KEYS must be a JSON object of kid to secret")
    if not parsed:
        return {}
    ring: dict[str, dict[str, object]] = {}
    for kid, value in parsed.items():
        _kid(str(kid))
        if isinstance(value, str):
            ring[str(kid)] = {"secret": _secret_bytes(value), "purposes": ["identifier"], "active": False}
        elif isinstance(value, dict):
            secret = value.get("secret")
            if not isinstance(secret, str):
                raise KeyCustodyError("GAB_HMAC_KEYS entries need a secret string")
            purposes = value.get("purposes") or ["identifier"]
            if not isinstance(purposes, list) or not purposes:
                raise KeyCustodyError("GAB_HMAC_KEYS purposes must be a non-empty list")
            for purpose in purposes:
                _purpose(str(purpose))
            ring[str(kid)] = {
                "secret": _secret_bytes(secret),
                "purposes": [str(item) for item in purposes],
                "active": bool(value.get("active")),
            }
        else:
            raise KeyCustodyError("GAB_HMAC_KEYS entries must be a secret or an object")
    return ring


def _parse_wrapped_hmac(raw: str | None) -> dict[str, list[dict[str, object]]]:
    text = _blank(raw)
    if text is None:
        return {}
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        raise KeyCustodyError("GAB_KMS_WRAPPED_HMAC_KEYS is not valid JSON") from exc
    if not isinstance(parsed, dict):
        raise KeyCustodyError("GAB_KMS_WRAPPED_HMAC_KEYS must be a JSON object")
    wrapped: dict[str, list[dict[str, object]]] = {}
    for purpose, value in parsed.items():
        _purpose(str(purpose))
        records = value if isinstance(value, list) else [value]
        normalized = []
        for record in records:
            if not isinstance(record, dict):
                raise KeyCustodyError("wrapped HMAC records must be objects")
            kid = record.get("kid")
            blob = record.get("wrapped")
            if not isinstance(kid, str) or not isinstance(blob, str):
                raise KeyCustodyError("wrapped HMAC records need kid and wrapped")
            normalized.append({"kid": kid, "wrapped": blob, "active": bool(record.get("active"))})
        wrapped[str(purpose)] = normalized
    return wrapped


def _parse_active(raw: str | None) -> tuple[dict[str, str] | None, bool]:
    """Return ``(mapping, strict)``. A bare kid is not strict: purposes it does not serve are skipped."""

    text = _blank(raw)
    if text is None:
        return None, True
    if text.startswith("{"):
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as exc:
            raise KeyCustodyError("GAB_HMAC_ACTIVE_KID is not valid JSON") from exc
        if not isinstance(parsed, dict):
            raise KeyCustodyError("GAB_HMAC_ACTIVE_KID object must map purpose to kid")
        return {str(purpose): str(kid) for purpose, kid in parsed.items()}, True
    return {"identifier": text, "rate": text, "subject": text, "network": text}, False


def _apply_active_map(
    current: dict[str, str],
    available: dict[str, list[str]],
    active: dict[str, str] | None,
    *,
    strict: bool,
) -> None:
    if not active:
        return
    applied = 0
    for purpose, kid in active.items():
        _purpose(purpose)
        if kid not in available.get(purpose, []):
            if strict:
                raise KeyCustodyError(f"active kid {kid} is not enabled for {purpose}")
            continue
        current[purpose] = kid
        applied += 1
    if applied == 0:
        raise KeyCustodyError("active kid is not enabled for any configured purpose")


def _normalize_ring(ring: dict[str, dict[str, object]]) -> dict[str, dict[str, object]]:
    cleaned: dict[str, dict[str, object]] = {}
    for kid, record in ring.items():
        secret = record.get("secret")
        purposes = record.get("purposes")
        if not isinstance(secret, bytes) or len(secret) != 32:
            raise KeyCustodyError("key material must be 32 bytes")
        if not isinstance(purposes, list) or not purposes:
            raise KeyCustodyError("each key needs a purpose")
        for purpose in purposes:
            _purpose(str(purpose))
        cleaned[_kid(str(kid))] = {
            "secret": secret,
            "purposes": [str(item) for item in purposes],
            "active": bool(record.get("active")),
        }
    return cleaned


def _secret_bytes(value: str) -> bytes:
    try:
        raw = _b64decode(value)
    except ValueError as exc:
        raise KeyCustodyError("a key secret is not valid base64") from exc
    if len(raw) != 32:
        raise KeyCustodyError("a key secret must decode to 32 bytes")
    return raw


def _encode_seal(subject: str, dek: bytes, plaintext: bytes, wrapped: bytes) -> str:
    nonce = os.urandom(12)
    ciphertext = _AESGCM(dek).encrypt(nonce, plaintext, _seal_aad(subject))
    return ".".join(
        [
            "gabseal1",
            "embedded",
            _b64encode(subject.encode("utf-8")),
            _b64encode(nonce),
            _b64encode(ciphertext),
            _b64encode(wrapped),
        ]
    )


def _decode_seal(encoded: str) -> tuple[str, bytes, bytes, bytes]:
    parts = encoded.split(".")
    if len(parts) != 6 or parts[0] != "gabseal1" or parts[1] != "embedded":
        raise KeyCustodyError("ciphertext did not open")
    try:
        subject = _b64decode(parts[2]).decode("utf-8")
        nonce = _b64decode(parts[3])
        ciphertext = _b64decode(parts[4])
        wrapped = _b64decode(parts[5])
    except (ValueError, UnicodeError) as exc:
        raise KeyCustodyError("ciphertext did not open") from exc
    return subject, wrapped, nonce, ciphertext


def _subject_ref_match(provider, subject_id: str, embedded: str) -> bool:
    matched = False
    embedded_digest = _digest(embedded)
    for ref in provider.subject_refs(subject_id):
        matched = hmac.compare_digest(embedded_digest, _digest(ref)) or matched
    return matched


def _hkdf(ikm: bytes, info: bytes) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    return HKDF(algorithm=hashes.SHA256(), length=32, salt=_HKDF_SALT, info=info).derive(ikm)


def _wrap_key(kek: bytes) -> bytes:
    return _hkdf(kek, _HKDF_WRAP_INFO)


def _hmac_key(secret: bytes, purpose: str) -> bytes:
    return _hkdf(secret, _HKDF_HMAC_INFO + b"\x00" + purpose.encode("utf-8"))


def _wrap_with_aes(kek: bytes, kek_id: str, dek: bytes, aad: bytes) -> bytes:
    nonce = os.urandom(12)
    ciphertext = _AESGCM(_wrap_key(kek)).encrypt(nonce, dek, aad)
    kid = kek_id.encode("utf-8")
    if len(kid) > 255:
        raise KeyCustodyError("kek id is too long")
    return bytes([1, len(kid)]) + kid + nonce + ciphertext


def _split_wrapped(wrapped: bytes) -> tuple[str, bytes, bytes]:
    if len(wrapped) < 2 + 12 + 16 or wrapped[0] != 1:
        raise KeyCustodyError("wrapped data key is not valid")
    length = wrapped[1]
    start = 2 + length
    if start + 12 > len(wrapped):
        raise KeyCustodyError("wrapped data key is not valid")
    try:
        kid = wrapped[2:start].decode("utf-8")
        _kid(kid)
    except (UnicodeError, KeyCustodyError) as exc:
        raise KeyCustodyError("wrapped data key is not valid") from exc
    nonce = wrapped[start : start + 12]
    ciphertext = wrapped[start + 12 :]
    return kid, nonce, ciphertext


def _pack_kms_dek(key_id: str, blob: bytes) -> bytes:
    encoded = key_id.encode("utf-8")
    if len(encoded) > 2048:
        raise KeyCustodyError("KMS key id is too long")
    return b"kms1" + len(encoded).to_bytes(2, "big") + encoded + blob


def _unpack_kms_dek(wrapped: bytes) -> tuple[str, bytes]:
    if len(wrapped) < 6 or not wrapped.startswith(b"kms1"):
        raise KeyCustodyError("wrapped data key is not valid")
    length = int.from_bytes(wrapped[4:6], "big")
    start = 6 + length
    if start > len(wrapped):
        raise KeyCustodyError("wrapped data key is not valid")
    try:
        key_id = wrapped[6:start].decode("utf-8")
    except UnicodeError as exc:
        raise KeyCustodyError("wrapped data key is not valid") from exc
    return key_id, wrapped[start:]


def _kms_call(call):
    """Run a KMS call. The public error names the outcome and omits the AWS message."""

    try:
        return call()
    except KeyCustodyError:
        raise
    except Exception as exc:  # noqa: BLE001 — KMS failures must not echo key material
        raise KeyCustodyError(_kms_public_message(exc)) from None


def _kms_public_message(exc: BaseException) -> str:
    code = ""
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        error = response.get("Error")
        if isinstance(error, dict):
            code = str(error.get("Code", ""))
    name = type(exc).__name__
    if code in {"DisabledException", "KMSInvalidStateException"}:
        return "KMS key is disabled or pending deletion"
    if code in {"AccessDeniedException", "UnauthorizedException"}:
        return "KMS denied the request"
    if code in {"ThrottlingException", "LimitExceededException", "TooManyRequestsException"}:
        return "KMS throttled the request"
    if code == "InvalidCiphertextException" or name in {"InvalidTag"}:
        return "KMS did not unwrap the data key"
    if "Timeout" in name or code in {"RequestTimeout", "RequestTimeoutException"}:
        return "KMS request timed out"
    return "KMS request failed"


class _SubjectRefRing:
    """Active subject-reference secret, then older ones used only for lookup."""

    def __init__(self, subject_key: bytes, previous_keys: tuple[bytes, ...] = ()) -> None:
        self._keys = [_subject_key(subject_key)]
        for key in previous_keys:
            material = _subject_key(key)
            if any(hmac.compare_digest(material, current) for current in self._keys):
                continue
            self._keys.append(material)

    def subject_ref(self, subject_id: str) -> str:
        return opaque_subject(subject_id, self._keys[0])

    def refs(self, subject_id: str) -> list[str]:
        return [opaque_subject(subject_id, key) for key in self._keys]


def _subject_key(key: bytes) -> bytes:
    if not isinstance(key, bytes) or len(key) != 32:
        raise KeyCustodyError("subject ref key must be 32 bytes")
    return bytes(key)


def subject_ref_key_problem(raw: str | None) -> str | None:
    """Return an error when a subject ref key is set but not usable.

    An unset value returns None. The text does not include the key.
    """

    if _blank(raw) is None:
        return None
    try:
        _parse_subject_key(raw)
    except KeyCustodyError as exc:
        return str(exc)
    return None


def _parse_subject_key(raw: str | None) -> bytes | None:
    text = _blank(raw)
    if text is None:
        return None
    try:
        decoded = _b64decode(text)
    except ValueError as exc:
        raise KeyCustodyError("GAB_SUBJECT_REF_KEY is not valid base64") from exc
    if len(decoded) != 32:
        raise KeyCustodyError("GAB_SUBJECT_REF_KEY must decode to 32 bytes")
    return decoded


def _stored_wrapped(row) -> bytes:
    if row is None or row[0] is None:
        raise KeyCustodyError("subject data key was not stored")
    try:
        return _b64decode(row[0])
    except ValueError as exc:
        raise KeyCustodyError("stored data key is not valid") from exc


def _same_bytes(left: bytes, right: bytes) -> bool:
    if len(left) != len(right):
        return False
    return hmac.compare_digest(left, right)


def _open_aes(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    try:
        return _AESGCM(key).decrypt(nonce, ciphertext, aad)
    except Exception as exc:  # noqa: BLE001 — authentication failures stay generic
        raise KeyCustodyError("ciphertext did not open") from exc


def _AESGCM(key: bytes):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    return AESGCM(key)


def _dek_aad(subject: str) -> bytes:
    return _DEK_AAD + b"\x00" + subject.encode("utf-8")


def _seal_aad(subject: str) -> bytes:
    return _SEAL_AAD + b"\x00" + subject.encode("utf-8")


def _wipe(secret: bytes) -> None:
    # CPython bytes are immutable. Best-effort overwrite of a private copy.
    buf = bytearray(secret)
    for index in range(len(buf)):
        buf[index] = 0


def _digest(value: str) -> bytes:
    return hashlib.sha256(value.encode("utf-8")).digest()


def _b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _purpose(purpose: str) -> str:
    if purpose not in _PURPOSES:
        raise KeyCustodyError(f"unknown key purpose {purpose}")
    return purpose


def _kid(kid: str) -> str:
    if not kid or len(kid) > _KID_MAX:
        raise KeyCustodyError("key id is missing or too long")
    if kid[0] not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789":
        raise KeyCustodyError("key id must start with a letter or digit")
    allowed = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-"
    if any(ch not in allowed for ch in kid):
        raise KeyCustodyError("key id has characters outside letters, digits, dot, underscore, and hyphen")
    return kid


def _value(value: str) -> str:
    if not isinstance(value, str) or value == "":
        raise KeyCustodyError("HMAC value is empty")
    if len(value) > 2000:
        raise KeyCustodyError("HMAC value is too long")
    return value


def _subject(subject_id: str) -> str:
    if not isinstance(subject_id, str) or not subject_id.strip():
        raise KeyCustodyError("subject id is empty")
    text = subject_id.strip()
    if len(text) > 200 or any(ord(ch) < 33 or ord(ch) > 126 for ch in text):
        raise KeyCustodyError("subject id is not a printable identifier")
    return text


def _kms_key_id(value: str) -> str:
    text = value.strip()
    if not text or len(text) > 2048 or any(ch.isspace() for ch in text):
        raise KeyCustodyError("GAB_KMS_KEY_ID is missing or not a single token")
    return text


def _region(value: str) -> str:
    text = value.strip()
    parts = text.split("-")
    if len(parts) < 3 or not all(part.isalnum() for part in parts):
        raise KeyCustodyError("GAB_KMS_REGION is not a region name")
    return text


def _blank(value: str | None) -> str | None:
    if value is None:
        return None
    text = value.strip()
    return text or None
