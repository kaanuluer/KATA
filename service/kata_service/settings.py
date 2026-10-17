# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: Apache-2.0
"""Environment for the deployment service. Secrets stay in the host, not in the repo."""

from __future__ import annotations

import base64
import json
import logging
import os
from dataclasses import dataclass, field

from kata_intent.errors import KataError
from kata_intent.keys import PrivateKey, public_key_from_jwk

from kata_service.defenses import ScorePolicy
from kata_service.keys import KeyCustodyError, provider_from_env, subject_ref_key_problem
from kata_service.score_model import ScoreWeights, weights_from_json

DEFAULT_FX_SOURCE_URL = "https://api.frankfurter.dev/v1"
REVOCATION_MAX_AGE_SECONDS = 300
NOTIFIER_JWK_UNUSABLE = "KATA_PUSH_NOTIFIER_JWK is not a usable public JWK"
SUBJECT_REF_UNUSABLE = "GAB_SUBJECT_REF_KEY is not a usable subject ref key"
log = logging.getLogger("kata_service.settings")


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
    score_policy: ScorePolicy = field(default_factory=ScorePolicy)
    consortium_match_threshold: int = 2
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_user: str | None = None
    smtp_password: str | None = None
    smtp_from: str | None = None
    public_base_url: str = "http://127.0.0.1:8765"
    verify_rate_limit_per_minute: int = 60
    inquiry_rate_limit_per_minute: int = 30
    report_rate_limit_per_minute: int = 10
    deployment_env: str = "production"
    step_up_approval: bool = False
    approval_ttl_seconds: int = 300
    vapid_public_key: str | None = None
    vapid_private_key: str | None = None
    vapid_subject: str | None = None
    key_provider: object | None = None
    push_notifier_unusable: bool = False
    subject_ref_unusable: bool = False
    master_key_configured: bool = False
    keyed_identifiers: bool = False
    hmac_rate_subject: bool = False
    stop_plaintext_email: bool = False

    def log_key(self) -> PrivateKey | None:
        if self.log_signing_seed is None:
            return None
        return PrivateKey(self.log_signing_seed, "EdDSA")


def settings_from_env(environ: dict[str, str] | None = None) -> Settings:
    """Read deployment settings. A bad notifier JWK does not crash import.

    That key is not a process-wide configuration error. Push reports it as 503.
    The parser text and the JWK are not stored. A set but unusable subject ref
    key is logged as one fixed sentence. The value is not logged and is not
    stored in config_error.
    """

    env = os.environ if environ is None else environ
    database_url = _blank(env.get("DATABASE_URL")) or _blank(env.get("POSTGRES_URL"))
    schema_url = _blank(env.get("DATABASE_URL_UNPOOLED")) or _blank(env.get("POSTGRES_URL_NON_POOLING")) or database_url
    error = None
    deployment_env = (_blank(env.get("GAB_ENV")) or "production").lower()
    if deployment_env not in {"production", "sandbox"}:
        error = "GAB_ENV must be production or sandbox"
        deployment_env = "production"
    seed = None
    notifier = None
    notifier_unusable = False
    published: tuple[dict, ...] = ()
    weights = ScoreWeights()
    key_provider = None
    subject_ref_unusable = False
    provider_env = env
    if subject_ref_key_problem(env.get("GAB_SUBJECT_REF_KEY")) is not None:
        log.error(SUBJECT_REF_UNUSABLE)
        subject_ref_unusable = True
        provider_env = {key: value for key, value in env.items() if key != "GAB_SUBJECT_REF_KEY"}
    master_key_configured = _blank(env.get("GAB_MASTER_KEY")) is not None
    try:
        seed = _seed(env.get("KATA_LOG_SIGNING_SEED"))
    except ValueError as exc:
        if error is None:
            error = str(exc)
    try:
        notifier = _notifier(env.get("KATA_PUSH_NOTIFIER_JWK"))
    except (KataError, ValueError, json.JSONDecodeError):
        notifier = None
        if _blank(env.get("KATA_PUSH_NOTIFIER_JWK")) is not None:
            notifier_unusable = True
    try:
        published = _published(env.get("KATA_PUBLISHED_KEYS"))
        weights = weights_from_json(_blank(env.get("GAB_SCORE_WEIGHTS")))
        if error is None:
            key_provider = provider_from_env(provider_env, deployment_env=deployment_env)
    except (KataError, ValueError, json.JSONDecodeError, KeyCustodyError) as exc:
        if error is None:
            error = str(exc)
    keyed_identifiers = _flag(env.get("GAB_KEYED_IDENTIFIERS"))
    hmac_rate_subject = _flag(env.get("GAB_HMAC_RATE_SUBJECT"))
    stop_plaintext_email = _flag(env.get("GAB_STOP_PLAINTEXT_EMAIL"))
    if error is None and stop_plaintext_email and not keyed_identifiers:
        error = "GAB_STOP_PLAINTEXT_EMAIL requires GAB_KEYED_IDENTIFIERS=1"
    if error is None and (keyed_identifiers or hmac_rate_subject) and key_provider is None:
        error = "keyed identifiers and rate subjects need GAB_KEY_PROVIDER"
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
        score_policy=_score_policy(env, weights),
        consortium_match_threshold=_positive_int(env.get("GAB_CONSORTIUM_MATCH_THRESHOLD"), 2),
        smtp_host=_blank(env.get("GAB_SMTP_HOST")),
        smtp_port=_positive_int(env.get("GAB_SMTP_PORT"), 587),
        smtp_user=_blank(env.get("GAB_SMTP_USER")),
        smtp_password=_blank(env.get("GAB_SMTP_PASSWORD")),
        smtp_from=_blank(env.get("GAB_SMTP_FROM")),
        public_base_url=_blank(env.get("GAB_PUBLIC_BASE_URL")) or "http://127.0.0.1:8765",
        verify_rate_limit_per_minute=_positive_int(env.get("GAB_VERIFY_RATE_LIMIT_PER_MINUTE"), 60),
        inquiry_rate_limit_per_minute=_positive_int(env.get("GAB_INQUIRY_RATE_LIMIT_PER_MINUTE"), 30),
        report_rate_limit_per_minute=_positive_int(env.get("GAB_REPORT_RATE_LIMIT_PER_MINUTE"), 10),
        deployment_env=deployment_env,
        step_up_approval=_flag(env.get("GAB_STEP_UP_APPROVAL")),
        approval_ttl_seconds=min(_positive_int(env.get("GAB_STEP_UP_TTL_SECONDS"), 300), 900),
        vapid_public_key=_blank(env.get("GAB_VAPID_PUBLIC_KEY")),
        vapid_private_key=_blank(env.get("GAB_VAPID_PRIVATE_KEY")),
        vapid_subject=_blank(env.get("GAB_VAPID_SUBJECT")),
        key_provider=key_provider,
        push_notifier_unusable=notifier_unusable,
        subject_ref_unusable=subject_ref_unusable,
        master_key_configured=master_key_configured,
        keyed_identifiers=keyed_identifiers,
        hmac_rate_subject=hmac_rate_subject,
        stop_plaintext_email=stop_plaintext_email,
    )


def _score_policy(env: dict[str, str], weights: ScoreWeights | None = None) -> ScorePolicy:
    master = _blank(env.get("GAB_DEFENSES"))
    default_on = True if master is None else master.lower() in {"1", "true", "yes"}

    def flag(name: str) -> bool:
        raw = _blank(env.get(name))
        if raw is None:
            return default_on
        return raw.lower() in {"1", "true", "yes"}

    weight = _blank(env.get("GAB_NEW_REPORTER_WEIGHT"))
    try:
        new_weight = float(weight) if weight is not None else 0.3
    except ValueError:
        new_weight = 0.3
    return ScorePolicy(
        require_transaction_link=flag("GAB_REQUIRE_REPORT_LINK"),
        link_quality=flag("GAB_LINK_QUALITY"),
        link_min_amount=_positive_int(env.get("GAB_LINK_MIN_AMOUNT"), 5),
        link_full_amount=_positive_int(env.get("GAB_LINK_FULL_AMOUNT"), 100),
        link_thin_weight=_unit_float(env.get("GAB_LINK_THIN_WEIGHT"), 0.25),
        link_min_age_days=_positive_int(env.get("GAB_LINK_MIN_AGE_DAYS"), 1),
        link_min_counterparties=_positive_int(env.get("GAB_LINK_MIN_COUNTERPARTIES"), 2),
        reporter_reputation=flag("GAB_REPORTER_REPUTATION"),
        report_consistency=flag("GAB_REPORT_CONSISTENCY"),
        positive_cap=flag("GAB_POSITIVE_CAP"),
        settled_cap_total=_positive_int(env.get("GAB_SETTLED_CAP_TOTAL"), 25),
        settled_cap_per_reporter=_positive_int(env.get("GAB_SETTLED_CAP_PER_REPORTER"), 16),
        settled_cap_scales=flag("GAB_SETTLED_CAP_SCALES"),
        operator_history=_optional_flag(env, "GAB_OPERATOR_HISTORY", True),
        operator_history_days=_positive_int(env.get("GAB_OPERATOR_HISTORY_DAYS"), 90),
        new_reporter_days=_positive_int(env.get("GAB_NEW_REPORTER_DAYS"), 30),
        new_reporter_weight=new_weight,
        ring_detection=flag("GAB_RING_DETECTION"),
        ring_min_cluster=_positive_int(env.get("GAB_RING_MIN_CLUSTER"), 3),
        ring_internal_ratio=_unit_float(env.get("GAB_RING_INTERNAL_RATIO"), 0.8),
        velocity=flag("GAB_VELOCITY"),
        velocity_adaptive=flag("GAB_VELOCITY_ADAPTIVE"),
        velocity_daily_count=_positive_int(env.get("GAB_VELOCITY_DAILY_COUNT"), 25),
        velocity_daily_amount=_positive_int(env.get("GAB_VELOCITY_DAILY_AMOUNT"), 15000),
        velocity_burst_multiple=float(_positive_int(env.get("GAB_VELOCITY_BURST_MULTIPLE"), 3)),
        velocity_quiet_days=_positive_int(env.get("GAB_VELOCITY_QUIET_DAYS"), 7),
        velocity_cashout_amount=_positive_int(env.get("GAB_VELOCITY_CASHOUT_AMOUNT"), 500),
        velocity_high_score=_positive_int(env.get("GAB_VELOCITY_HIGH_SCORE"), 750),
        rereg_link=flag("GAB_REREG_LINK"),
        rereg_lookback_days=_positive_int(env.get("GAB_REREG_LOOKBACK_DAYS"), 14),
        rereg_signal_lookback_days=_positive_int(env.get("GAB_REREG_SIGNAL_LOOKBACK_DAYS"), 90),
        rereg_malicious_lookback_days=_positive_int(env.get("GAB_REREG_MALICIOUS_LOOKBACK_DAYS"), 180),
        rereg_penalty=_positive_int(env.get("GAB_REREG_PENALTY"), 80),
        inherit_history=flag("GAB_INHERIT_HISTORY"),
        inherit_half_life_days=_positive_int(env.get("GAB_INHERIT_HALF_LIFE_DAYS"), 30),
        dispute_hold=flag("GAB_DISPUTE_HOLD"),
        require_proofing=_optional_flag(env, "GAB_REQUIRE_PROOFING", True),
        weights=weights or ScoreWeights(),
    )


def _optional_flag(env: dict[str, str], name: str, default: bool) -> bool:
    raw = _blank(env.get(name))
    if raw is None:
        return default
    return raw.lower() in {"1", "true", "yes"}


def _unit_float(value: str | None, default: float) -> float:
    text = _blank(value)
    if text is None:
        return default
    try:
        number = float(text)
    except ValueError:
        return default
    if number < 0 or number > 1:
        return default
    return number


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
