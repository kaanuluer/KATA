# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: Apache-2.0
"""Environment for the deployment service. Secrets stay in the host, not in the repo."""

from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass

from kata_intent.errors import KataError
from kata_intent.keys import PrivateKey, public_key_from_jwk

DEFAULT_FX_SOURCE_URL = "https://api.frankfurter.dev/v1"
REVOCATION_MAX_AGE_SECONDS = 300


@dataclass(frozen=True)
class Settings:
    database_url: str | None
    schema_url: str | None
    log_signing_seed: bytes | None
    push_notifier_jwk: dict | None
    append_token: str | None
    published_keys: tuple[dict, ...]
    fx_source_url: str
    config_error: str | None = None
    admin_token: str | None = None
    rate_limit_per_minute: int = 120
    demo: bool = False
    dev_mailbox: bool = False
    magic_link_ttl_seconds: int = 900
    session_ttl_seconds: int = 43200
    report_daily_cap: int = 20
    allow_demo_seed: bool = False

    def log_key(self) -> PrivateKey | None:
        if self.log_signing_seed is None:
            return None
        return PrivateKey(self.log_signing_seed, "EdDSA")


def settings_from_env(environ: dict[str, str] | None = None) -> Settings:
    """Read deployment settings. A bad public JWK is reported and does not crash import."""

    env = os.environ if environ is None else environ
    database_url = _blank(env.get("DATABASE_URL")) or _blank(env.get("POSTGRES_URL"))
    schema_url = _blank(env.get("DATABASE_URL_UNPOOLED")) or _blank(env.get("POSTGRES_URL_NON_POOLING")) or database_url
    error = None
    seed = None
    notifier = None
    published: tuple[dict, ...] = ()
    try:
        seed = _seed(env.get("KATA_LOG_SIGNING_SEED"))
        notifier = _notifier(env.get("KATA_PUSH_NOTIFIER_JWK"))
        published = _published(env.get("KATA_PUBLISHED_KEYS"))
    except (KataError, ValueError, json.JSONDecodeError) as exc:
        error = str(exc)
    return Settings(
        database_url=database_url,
        schema_url=schema_url,
        log_signing_seed=seed,
        push_notifier_jwk=notifier,
        append_token=_blank(env.get("KATA_APPEND_TOKEN")),
        published_keys=published,
        fx_source_url=_blank(env.get("KATA_FX_SOURCE_URL")) or DEFAULT_FX_SOURCE_URL,
        config_error=error,
        admin_token=_blank(env.get("GAB_ADMIN_TOKEN")),
        rate_limit_per_minute=_positive_int(env.get("GAB_RATE_LIMIT_PER_MINUTE"), 120),
        demo=_flag(env.get("GAB_DEMO")),
        dev_mailbox=_flag(env.get("GAB_DEV_MAILBOX")),
        magic_link_ttl_seconds=_positive_int(env.get("GAB_MAGIC_LINK_TTL_SECONDS"), 900),
        session_ttl_seconds=_positive_int(env.get("GAB_SESSION_TTL_SECONDS"), 43200),
        report_daily_cap=_positive_int(env.get("GAB_REPORT_DAILY_CAP"), 20),
        allow_demo_seed=_flag(env.get("GAB_ALLOW_DEMO_SEED")),
    )


def _flag(value: str | None) -> bool:
    return (_blank(value) or "").lower() in {"1", "true", "yes"}


def _positive_int(value: str | None, default: int) -> int:
    text = _blank(value)
    if text is None:
        return default
    try:
        number = int(text)
    except ValueError:
        return default
    return number if number > 0 else default


def _blank(value: str | None) -> str | None:
    if value is None:
        return None
    text = value.strip()
    return text or None


def _seed(value: str | None) -> bytes | None:
    text = _blank(value)
    if text is None:
        return None
    padding = "=" * (-len(text) % 4)
    try:
        raw = base64.b64decode(text + padding, validate=False)
    except Exception as exc:  # noqa: BLE001 — one configuration error for the operator
        raise ValueError("KATA_LOG_SIGNING_SEED is not base64") from exc
    if len(raw) != 32:
        raise ValueError("KATA_LOG_SIGNING_SEED must decode to 32 bytes")
    return raw


def _notifier(value: str | None) -> dict | None:
    text = _blank(value)
    if text is None:
        return None
    parsed = json.loads(text)
    if not isinstance(parsed, dict):
        raise ValueError("KATA_PUSH_NOTIFIER_JWK must be a public JWK object")
    public_key_from_jwk(parsed)
    return parsed


def _published(value: str | None) -> tuple[dict, ...]:
    text = _blank(value)
    if text is None:
        return ()
    parsed = json.loads(text)
    if not isinstance(parsed, list):
        raise ValueError("KATA_PUBLISHED_KEYS must be a JSON array")
    records = []
    for item in parsed:
        if not isinstance(item, dict) or not isinstance(item.get("public_key"), dict):
            raise ValueError("KATA_PUBLISHED_KEYS records need a public_key object")
        public_key_from_jwk(item["public_key"])
        records.append(item)
    return tuple(records)
