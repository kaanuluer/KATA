# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Global Agent Bureau domain logic.

Organizations, agents, signed intents, inquiries, incidents, the trust score,
alerts, and the individual portal share one repository. Email addresses stay
on the login tables and are not copied into inquiries, the audit log, or the
transparency log.
"""

from __future__ import annotations

import hashlib
import hmac
import html
import json
import re
import secrets
import threading
import time
from contextvars import ContextVar, Token
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any, Protocol
from urllib.parse import urlparse

from kata_intent.agreement import Agreement
from kata_intent.canonical import canonical_bytes
from kata_intent.errors import KataError
from kata_intent.jws import sign_jws
from kata_intent.keys import PrivateKey, public_key_from_jwk
from kata_intent.values import coerce, hash_document

from kata_service.score_model import ScoreWeights
from kata_service.defenses import (
    ScoreContext,
    ScorePolicy,
    agent_is_denied,
    cap_settled_points,
    cluster_edges,
    consistency_multiplier,
    report_is_negative,
    age_days,
    decay_factor,
    effective_assurance,
    inheritance_penalty,
    link_strength,
    lookback_days,
    report_is_linked,
    reporter_is_young,
    reputation_multiplier,
    scaled_settled_caps,
    velocity_reason,
    window_totals,
    within_days,
)

ORG_TYPES = ("agent_operator", "wallet", "bank_issuer", "processor_psp", "merchant")
SCOPES = (
    "registry:read",
    "registry:write",
    "verify",
    "inquire",
    "report",
    "alerts",
    "keys:manage",
)
PURPOSE_CODES = (
    "payment_authorization",
    "account_opening",
    "fraud_investigation",
    "dispute_resolution",
    "ongoing_monitoring",
    "agent_onboarding",
)
REPORT_KINDS = ("transaction_outcome", "fraud_incident", "chargeback", "policy_violation")
AGENT_STATUSES = ("active", "suspended", "revoked")
VERIFICATION_LEVELS = ("unverified", "key_bound", "operator_verified", "institution_attested")
OPERATOR_LEVELS = ("unverified", "key_bound", "operator_verified")
DISPUTE_STATUSES = ("open", "under_review", "resolved")
DISPUTE_OUTCOMES = ("upheld", "rejected", "partial")
PROOFING_METHODS = ("key_binding", "operator_review", "institution_attestation")
_AGENT_ID = re.compile(r"^[A-Za-z0-9._-]{1,80}$")
_EVIDENCE = re.compile(r"^sha256:[0-9a-f]{64}$")
_EMAIL = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,120}$")
ALERT_TYP = "kata-bureau-alert+jws"


class BureauError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


_test_mode: ContextVar[bool] = ContextVar("gab_test_mode", default=False)


def in_test_mode() -> bool:
    return bool(_test_mode.get())


def use_test_mode(enabled: bool) -> Token[bool]:
    return _test_mode.set(bool(enabled))


def reset_test_mode(token: Token[bool]) -> None:
    _test_mode.reset(token)


def _json_within_depth(value: Any) -> bool:
    try:
        coerce(value)
    except KataError:
        return False
    return True


def reject_deep_json(body: Any) -> None:
    """Refuse a JSON body nested past the document limit before any lookup.

    The action document keeps the existing 32-level limit. The HTTP envelope
    around that document is not counted as an extra level.
    """

    if not isinstance(body, dict) or _json_within_depth(body):
        return
    action = body.get("action")
    if isinstance(action, dict) and _json_within_depth(action):
        rest = {key: value for key, value in body.items() if key != "action"}
        if _json_within_depth(rest):
            return
    raise BureauError(400, "document is nested too deeply")


def _stamp_env(record: dict[str, Any]) -> dict[str, Any]:
    record["is_test"] = in_test_mode()
    return dict(record)


def _in_env(record: dict[str, Any]) -> bool:
    return bool(record.get("is_test")) == in_test_mode()


def _env_key(value: str) -> str:
    return f"{int(in_test_mode())}:{value}"


@dataclass
class Auth:
    admin: bool = False
    org_id: str | None = None
    key_id: str | None = None
    principal_id: str | None = None
    scopes: frozenset[str] = field(default_factory=frozenset)
    kind: str = "anonymous"
    test: bool = False


class Mailer(Protocol):
    def send_magic_link(self, email: str, url: str) -> None: ...


class WebhookSender(Protocol):
    def send(self, url: str, body: dict[str, Any]) -> None: ...


class ConsoleMailer:
    """Development sender. The link is printed, not delivered to a network."""

    def send_magic_link(self, email: str, url: str) -> None:
        print(f"GAB magic link for {email}: {url}", flush=True)


class SilentMailer:
    """No transport. The link stays in the store and is not printed."""

    def send_magic_link(self, email: str, url: str) -> None:
        return None


def magic_link_message(email: str, url: str, from_addr: str, *, ttl_seconds: int = 900):
    """Plain text plus an HTML alternative. The token stays in the URL fragment."""

    from email.message import EmailMessage

    plain, rich = magic_link_bodies(url, ttl_seconds=ttl_seconds)
    message = EmailMessage()
    message["Subject"] = "Your Global Agent Bureau sign-in link"
    message["From"] = from_addr
    message["To"] = email
    message.set_content(plain)
    message.add_alternative(rich, subtype="html")
    return message


def magic_link_bodies(url: str, *, ttl_seconds: int = 900) -> tuple[str, str]:
    expiry = _expiry_phrase(ttl_seconds)
    ignore = "If you did not ask for it, ignore this message."
    plain = (
        "GAB_\n"
        "Global Agent Bureau\n\n"
        "Use this link to sign in.\n"
        f"{expiry}\n"
        f"{ignore}\n\n"
        f"{url}\n\n"
        "Global Agent Bureau is an agent bureau. Powered by KATA.\n"
    )
    return plain, _magic_link_html(url, expiry=expiry, ignore=ignore)


def _expiry_phrase(seconds: int) -> str:
    if seconds >= 60 and seconds % 60 == 0:
        minutes = seconds // 60
        unit = "minute" if minutes == 1 else "minutes"
        return f"This link expires in {minutes} {unit}."
    unit = "second" if seconds == 1 else "seconds"
    return f"This link expires in {seconds} {unit}."


def _magic_link_html(url: str, *, expiry: str, ignore: str) -> str:
    safe_url = html.escape(url, quote=True)
    safe_expiry = html.escape(expiry)
    safe_ignore = html.escape(ignore)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<meta name="supported-color-schemes" content="dark">
<title>Your Global Agent Bureau sign-in link</title>
</head>
<body style="margin:0;padding:0;background:#13203B;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="#13203B" style="background:#13203B;margin:0;padding:0;">
<tr>
<td align="center" style="padding:32px 16px;">
<table role="presentation" width="560" cellpadding="0" cellspacing="0" border="0" bgcolor="#0C4E57" style="width:560px;max-width:560px;background:#0C4E57;border-radius:16px;">
<tr>
<td style="padding:28px 28px 8px 28px;">
<table role="presentation" cellpadding="0" cellspacing="0" border="0" bgcolor="#F3F7F7" style="background:#F3F7F7;border-radius:10px;">
<tr>
<td style="padding:8px 10px;line-height:0;font-size:0;"><img src="https://globalagentbureau.com/assets/gab-logo.png" width="371" height="198" alt="GAB_" border="0" style="display:block;width:371px;max-width:100%;height:auto;border:0;outline:none;text-decoration:none;"></td>
</tr>
</table>
</td>
</tr>
<tr>
<td style="padding:16px 28px 0 28px;font-family:Georgia,'Palatino Linotype',Palatino,serif;font-size:26px;line-height:1.25;color:#F3F7F7;">Sign in to Global Agent Bureau</td>
</tr>
<tr>
<td style="padding:12px 28px 0 28px;font-family:Arial,Helvetica,sans-serif;font-size:16px;line-height:1.5;color:#D8F7EE;">Global Agent Bureau is an agent bureau. Use the button to sign in. Powered by KATA.</td>
</tr>
<tr>
<td style="padding:24px 28px 0 28px;">
<table role="presentation" cellpadding="0" cellspacing="0" border="0">
<tr>
<td bgcolor="#4FE0C2" style="background:#4FE0C2;border-radius:999px;">
<a href="{safe_url}" style="display:inline-block;padding:14px 22px;font-family:Arial,Helvetica,sans-serif;font-size:16px;line-height:1;font-weight:bold;color:#12343A;text-decoration:none;">Sign in</a>
</td>
</tr>
</table>
</td>
</tr>
<tr>
<td style="padding:18px 28px 0 28px;font-family:Arial,Helvetica,sans-serif;font-size:13px;line-height:1.5;color:#E7F1F2;">Or copy this link:</td>
</tr>
<tr>
<td style="padding:6px 28px 0 28px;font-family:Arial,Helvetica,sans-serif;font-size:13px;line-height:1.45;color:#4FE0C2;word-break:break-all;"><a href="{safe_url}" style="color:#4FE0C2;text-decoration:underline;word-break:break-all;">{safe_url}</a></td>
</tr>
<tr>
<td style="padding:18px 28px 0 28px;font-family:Arial,Helvetica,sans-serif;font-size:14px;line-height:1.5;color:#F3F7F7;">{safe_expiry}</td>
</tr>
<tr>
<td style="padding:8px 28px 28px 28px;font-family:Arial,Helvetica,sans-serif;font-size:14px;line-height:1.5;color:#D8F7EE;">{safe_ignore}</td>
</tr>
</table>
</td>
</tr>
</table>
</body>
</html>
"""


class SmtpMailer:
    """STARTTLS SMTP. The password is not included in the text representation."""

    def __init__(self, host: str, port: int, user: str, password: str, from_addr: str, ttl_seconds: int = 900) -> None:
        self.host = host
        self.port = port
        self.user = user
        self._password = password
        self.from_addr = from_addr
        self.ttl_seconds = ttl_seconds

    def __repr__(self) -> str:
        return f"SmtpMailer(host={self.host!r}, port={self.port}, user={self.user!r})"

    def send_magic_link(self, email: str, url: str) -> None:
        import smtplib

        message = magic_link_message(email, url, self.from_addr, ttl_seconds=self.ttl_seconds)
        try:
            if self.port == 465:
                with smtplib.SMTP_SSL(self.host, self.port, timeout=10) as smtp:
                    smtp.login(self.user, self._password)
                    smtp.send_message(message)
                return
            with smtplib.SMTP(self.host, self.port, timeout=10) as smtp:
                smtp.ehlo()
                smtp.starttls()
                smtp.ehlo()
                smtp.login(self.user, self._password)
                smtp.send_message(message)
        except Exception as exc:
            raise BureauError(503, "the sign-in link could not be sent") from exc


def mailer_from_settings(settings: object) -> Mailer:
    """Use SMTP only when host, user, password, and from are all set."""

    host = getattr(settings, "smtp_host", None)
    user = getattr(settings, "smtp_user", None)
    password = getattr(settings, "smtp_password", None)
    sender = getattr(settings, "smtp_from", None)
    if host and user and password and sender:
        ttl = int(getattr(settings, "magic_link_ttl_seconds", 900) or 900)
        return SmtpMailer(host, int(getattr(settings, "smtp_port", 587) or 587), user, password, sender, ttl)
    if getattr(settings, "dev_mailbox", False) or getattr(settings, "demo", False):
        return ConsoleMailer()
    return SilentMailer()


class HttpWebhookSender:
    """POST a webhook once. The bureau records each attempt and retries around this."""

    def deliver(self, url: str, body: dict[str, Any]) -> tuple[str, int | None, str]:
        import urllib.error
        import urllib.request

        data = json.dumps(body).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json", "User-Agent": "gab-service/0.1"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=3) as response:
                response.read()
                code = getattr(response, "status", None)
                return "delivered", int(code) if code is not None else None, "delivered"
        except urllib.error.HTTPError as exc:
            return "failed", int(exc.code), "http_error"
        except TimeoutError:
            return "failed", None, "timeout"
        except Exception:
            return "failed", None, "refused"

    def send(self, url: str, body: dict[str, Any]) -> None:
        outcome, _http_status, _detail = self.deliver(url, body)
        if outcome != "delivered":
            raise BureauError(502, "webhook delivery failed")


class RecordingSender:
    def __init__(self) -> None:
        self.sent: list[tuple[str, dict[str, Any]]] = []

    def send(self, url: str, body: dict[str, Any]) -> None:
        self.sent.append((url, body))


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def email_hash(email: str) -> str:
    """Legacy unsalted SHA-256 of a normalized email.

    Login lookups use a keyed HMAC when GAB_KEYED_IDENTIFIERS is on. token_hash
    stays plain SHA-256 because its input is a high-entropy secret.
    """

    return hashlib.sha256(normalize_email(email).encode("utf-8")).hexdigest()


def normalize_email(email: str) -> str:
    return email.strip().lower()


def default_scopes(org_type: str) -> list[str]:
    if org_type == "agent_operator":
        return ["registry:read", "registry:write", "verify", "report", "alerts", "keys:manage"]
    if org_type in {"wallet", "bank_issuer"}:
        return ["registry:read", "registry:write", "inquire", "verify", "report", "alerts", "keys:manage"]
    return ["registry:read", "inquire", "verify", "report", "alerts", "keys:manage"]


def trust_score(
    *,
    verification_level: str,
    operator_status: str,
    operator_org_id: str,
    reports: list[dict[str, Any]],
    disputes: list[dict[str, Any]],
    reporter_types: dict[str, str],
    policy: ScorePolicy | None = None,
    context: ScoreContext | None = None,
) -> dict[str, Any]:
    """Explainable 0–1000 score for an agent. Individuals are not scored.

    Omitting policy uses ScorePolicy.legacy(), the formula from before the
    transaction link, reputation weight, positive cap, ring discount, and
    dispute hold. The service passes the configured policy.
    """

    policy = policy or ScorePolicy.legacy()
    context = context or ScoreContext()
    weights = policy.weights
    parts: list[tuple[str, int, str]] = []
    identity = weights.identity_points(verification_level)
    parts.append(("IDENTITY_ASSURANCE", identity, verification_level))
    if operator_status == "active":
        parts.append(("OPERATOR_VERIFICATION", weights.operator_active, "operator active"))
    else:
        parts.append(("OPERATOR_INACTIVE", weights.operator_inactive, operator_status))
    if context.identity_penalty:
        parts.append(("IDENTITY_LINK", -int(context.identity_penalty), "recently denied agent"))

    resolved = {
        item["report_id"]: item
        for item in disputes
        if item.get("status") == "resolved" and item.get("outcome")
    }
    best: dict[tuple[str, str], tuple[float, dict[str, Any]]] = {}
    for report in reports:
        if report.get("excluded"):
            continue
        if policy.require_transaction_link and not report_is_linked(report, context):
            continue
        strength = link_strength(report, policy, context)
        if strength <= 0:
            continue
        weight = weights.reporter_weight(reporter_types.get(report["reporter_org_id"], ""))
        weight *= strength
        if report["reporter_org_id"] == operator_org_id:
            weight *= weights.self_operator
        weight *= reputation_multiplier(report["reporter_org_id"], policy, context)
        weight *= consistency_multiplier(report, policy, context)
        dispute = resolved.get(report["report_id"])
        if dispute and dispute["outcome"] == "upheld":
            parts.append(("DISPUTE_UPHELD", 0, report["report_id"]))
            continue
        if dispute and dispute["outcome"] == "partial":
            weight *= 0.5
        key = (report["kind"], report["evidence_hash"])
        current = best.get(key)
        if current is None or weight > current[0]:
            best[key] = (weight, report)

    settled_grants: list[tuple[int, str]] = []
    held = False
    ring_discount = False
    for (_key, (weight, report)) in best.items():
        negative = _report_points(report, 1, weights)[0] < 0
        if (
            policy.dispute_hold
            and report["report_id"] in context.open_dispute_ids
            and negative
            and reporter_is_young(report["reporter_org_id"], policy, context)
        ):
            held = True
            continue
        if (
            policy.ring_detection
            and report.get("kind") == "transaction_outcome"
            and report.get("outcome") == "settled"
            and (report["reporter_org_id"], operator_org_id) in context.ring_edges
        ):
            ring_discount = True
            continue
        points, code = _report_points(report, weight, weights)
        if code == "SETTLED_ACTIVITY" and policy.positive_cap:
            settled_grants.append((points, report["reporter_org_id"]))
            continue
        if points:
            parts.append((code, points, report["kind"]))
    if settled_grants:
        per_reporter, total_cap = scaled_settled_caps(
            policy,
            counterparties=context.external_counterparties,
            volume=context.external_volume,
        )
        granted = cap_settled_points(
            settled_grants,
            per_reporter=per_reporter,
            total=total_cap,
        )
        if granted:
            parts.append(("SETTLED_ACTIVITY", granted, "capped settled credit"))
    if policy.inherit_history:
        inherited_total = 0
        for report in context.inherited_reports:
            if report.get("excluded"):
                continue
            inherited_weight = weights.reporter_weight(reporter_types.get(report.get("reporter_org_id", ""), ""))
            if report.get("reporter_org_id") == operator_org_id:
                inherited_weight *= weights.self_operator
            inherited_weight *= reputation_multiplier(str(report.get("reporter_org_id") or ""), policy, context)
            inherited_weight *= consistency_multiplier(report, policy, context)
            inherited_weight *= float(report.get("decay") or 0)
            points, _code = _report_points(report, inherited_weight, weights)
            if points < 0:
                inherited_total += points
        if inherited_total:
            parts.append(("INHERITED_HISTORY", inherited_total, "linked denied agent"))

    raw = weights.baseline + sum(points for _code, points, _detail in parts)
    score = max(0, min(1000, int(raw)))
    ranked = sorted(parts, key=lambda item: abs(item[1]), reverse=True)
    reasons = [
        {"code": code, "points": points, "detail": detail}
        for code, points, detail in ranked
        if points != 0
    ][:4]
    extras = []
    if held:
        extras.append({"code": "DISPUTE_HOLD", "points": 0, "detail": "open dispute against a young reporter"})
    if ring_discount:
        extras.append({"code": "RING_DISCOUNTED", "points": 0, "detail": "settled reports in a closed cluster"})
    for extra in extras:
        if len(reasons) < 4:
            reasons.append(extra)
    cold = not best
    if cold:
        reasons = [{"code": "COLD_START", "points": 0, "detail": "no contributing reports"}, *reasons][:4]
    return {
        "score": score,
        "risk": weights.risk(score),
        "model_version": weights.model_version,
        "reasons": reasons,
        "cold_start": cold,
    }


def _report_points(report: dict[str, Any], weight: float, weights: ScoreWeights) -> tuple[int, str]:
    base, code = weights.report_base(report["kind"], report.get("outcome") or "")
    if code == "REPORT":
        return (0, code)
    return (int(round(base * weight)), code)


class MemoryRepo:
    """Process-local bureau store. Tests and GAB_DEMO use this."""

    def __init__(self) -> None:
        self.orgs: dict[str, dict[str, Any]] = {}
        self.keys: dict[str, dict[str, Any]] = {}
        self.by_hash: dict[str, str] = {}
        self.audit: list[dict[str, Any]] = []
        self.rate: dict[tuple[str, str], int] = {}
        self.principals: dict[str, dict[str, Any]] = {}
        self.logins: dict[str, dict[str, Any]] = {}
        self.logins_by_hmac: dict[str, str] = {}
        self.org_logins_by_hmac: dict[str, str] = {}
        self.identifier_mode = None
        self.magic: dict[str, dict[str, Any]] = {}
        self.sessions: dict[str, dict[str, Any]] = {}
        self.passkeys: dict[str, dict[str, Any]] = {}
        self.challenges: dict[str, dict[str, Any]] = {}
        self.push_devices: dict[str, dict[str, Any]] = {}
        self.approvals: dict[str, dict[str, Any]] = {}
        self.org_logins: dict[str, dict[str, Any]] = {}
        self.agents: dict[str, dict[str, Any]] = {}
        self.by_fingerprint: dict[str, str] = {}
        self.agreements: dict[str, dict[str, Any]] = {}
        self.reports: list[dict[str, Any]] = []
        self.interactions: list[dict[str, Any]] = []
        self.identity_links: list[dict[str, Any]] = []
        self.agent_signals: list[dict[str, Any]] = []
        self.org_signals: list[dict[str, Any]] = []
        self.proofings: list[dict[str, Any]] = []
        self.consortium_members: dict[str, dict[str, Any]] = {}
        self.consortium_sightings: list[dict[str, Any]] = []
        self.inquiries: list[dict[str, Any]] = []
        self.subscriptions: list[dict[str, Any]] = []
        self.alerts: list[dict[str, Any]] = []
        self.deliveries: list[dict[str, Any]] = []
        self.disputes: list[dict[str, Any]] = []
        self.consent_events: list[dict[str, Any]] = []
        self.payloads: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()

    def migration_versions(self) -> list[str]:
        return [
            "001_bureau.sql",
            "002_defenses.sql",
            "003_proofing.sql",
            "004_consortium.sql",
            "005_org_signals.sql",
            "006_sandbox.sql",
            "006_webhook.sql",
            "007_partition.sql",
            "008_audit_environment.sql",
            "009_portal_devices.sql",
            "010_step_up.sql",
            "011_keyed_identifiers.sql",
            "012_consent_events.sql",
            "015_entity_kind.sql",
            "016_ledger_payloads.sql",
            "017_subject_deks.sql",
        ]

    def create_org(self, record: dict[str, Any]) -> None:
        with self._lock:
            self.orgs[record["org_id"]] = dict(record)

    def get_org(self, org_id: str) -> dict[str, Any] | None:
        with self._lock:
            item = self.orgs.get(org_id)
            return dict(item) if item else None

    def set_org_created_at(self, org_id: str, created_at: str) -> None:
        with self._lock:
            if org_id in self.orgs:
                self.orgs[org_id]["created_at"] = created_at

    def create_key(self, record: dict[str, Any]) -> None:
        with self._lock:
            self.keys[record["key_id"]] = dict(record)
            self.by_hash[record["secret_hash"]] = record["key_id"]

    def key_by_hash(self, secret_hash: str) -> dict[str, Any] | None:
        with self._lock:
            key_id = self.by_hash.get(secret_hash)
            if key_id is None:
                return None
            return dict(self.keys[key_id])

    def get_key(self, key_id: str) -> dict[str, Any] | None:
        with self._lock:
            item = self.keys.get(key_id)
            return dict(item) if item else None

    def list_keys(self, org_id: str) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(item) for item in self.keys.values() if item["org_id"] == org_id]

    def revoke_key(self, key_id: str, at: str) -> None:
        with self._lock:
            self.keys[key_id]["revoked_at"] = at

    def add_audit(self, record: dict[str, Any]) -> None:
        with self._lock:
            self.audit.append(dict(record))

    def list_audit(self, org_id: str | None, environment: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            rows = self.audit if org_id is None else [item for item in self.audit if item.get("org_id") == org_id]
            if environment is not None:
                rows = [item for item in rows if (item.get("environment") or "live") == environment]
            return [dict(item) for item in rows]

    def hit_rate(self, subject: str, window: str) -> int:
        with self._lock:
            key = (subject, window)
            self.rate[key] = self.rate.get(key, 0) + 1
            return self.rate[key]

    def purge_rate(self, before: str) -> int:
        with self._lock:
            stale = [key for key in self.rate if key[1] < before]
            for key in stale:
                del self.rate[key]
            return len(stale)

    def ensure_principal(self, principal_id: str, at: str) -> None:
        with self._lock:
            self.principals.setdefault(principal_id, {"principal_id": principal_id, "created_at": at})

    def insert_login(self, email: str, principal_id: str, at: str) -> str:
        """Bind an email once. A later call cannot move it to another principal."""

        with self._lock:
            current = self._find_login(email)
            material = {**self._login_material(email, principal_id), "principal_id": principal_id}
            if current is None:
                self._store_login(material["email_hash"], material, at, created=True)
                return "inserted"
            if current["principal_id"] != principal_id:
                return "conflict"
            self._store_login(current["email_hash"], {**current, **material, "email_hash": current["email_hash"]}, at, created=False)
            return "same"

    def upsert_login(self, email: str, principal_id: str, at: str) -> None:
        self.insert_login(email, principal_id, at)

    def login_by_email(self, email: str) -> dict[str, Any] | None:
        with self._lock:
            return self._copy_login(self._find_login(email))

    def login_by_hash(self, digest: str) -> dict[str, Any] | None:
        with self._lock:
            return self._copy_login(self._login_by_stored_digest(digest))

    def login_by_subject(self, subject_hmac: str | None, subject_hash: str) -> dict[str, Any] | None:
        with self._lock:
            if subject_hmac:
                found = self._login_by_stored_digest(subject_hmac)
                if found is not None:
                    return self._copy_login(found)
            return self._copy_login(self._login_by_stored_digest(subject_hash))

    def upsert_org_login(self, email: str, org_id: str, at: str) -> None:
        with self._lock:
            current = self._find_org_login(email)
            material = self._login_material(email, org_id)
            digest = current["email_hash"] if current is not None else material["email_hash"]
            self._store_org_login(digest, {**material, "org_id": org_id, "email_hash": digest}, at, created=current is None)

    def org_login_by_email(self, email: str) -> dict[str, Any] | None:
        with self._lock:
            return self._copy_org_login(self._find_org_login(email))

    def org_login_by_hash(self, digest: str) -> dict[str, Any] | None:
        with self._lock:
            return self._copy_org_login(self._org_login_by_stored_digest(digest))

    def org_login_by_subject(self, subject_hmac: str | None, subject_hash: str) -> dict[str, Any] | None:
        with self._lock:
            if subject_hmac:
                found = self._org_login_by_stored_digest(subject_hmac)
                if found is not None:
                    return self._copy_org_login(found)
            return self._copy_org_login(self._org_login_by_stored_digest(subject_hash))

    def _login_material(self, email: str, subject_id: str) -> dict[str, Any]:
        mode = self.identifier_mode
        if mode is None:
            return {"email_hash": email_hash(email), "email": normalize_email(email)}
        return mode.bind(email, subject_id)

    def _find_login(self, email: str) -> dict[str, Any] | None:
        mode = self.identifier_mode
        if mode is not None:
            for token in mode.candidates(email):
                found = self._login_by_stored_digest(token)
                if found is not None:
                    return found
        return self.logins.get(email_hash(email))

    def _login_by_stored_digest(self, digest: str) -> dict[str, Any] | None:
        item = self.logins.get(digest)
        if item is None:
            pointer = self.logins_by_hmac.get(digest)
            item = None if pointer is None else self.logins.get(pointer)
        return item

    def _store_login(self, digest: str, material: dict[str, Any], at: str, *, created: bool) -> None:
        current = self.logins.get(digest)
        record = {
            "email_hash": digest,
            "email": material.get("email", ""),
            "principal_id": material["principal_id"] if "principal_id" in material else current["principal_id"],
            "created_at": current["created_at"] if current is not None else at,
        }
        if "principal_id" in material and created:
            record["principal_id"] = material["principal_id"]
        elif current is not None:
            record["principal_id"] = current["principal_id"]
        else:
            record["principal_id"] = material["principal_id"]
        for key in ("email_hmac", "email_kid", "email_ciphertext"):
            if material.get(key):
                record[key] = material[key]
            elif current is not None and current.get(key):
                record[key] = current[key]
        self.logins[digest] = record
        if record.get("email_hmac"):
            self.logins_by_hmac[record["email_hmac"]] = digest

    def _copy_login(self, item: dict[str, Any] | None) -> dict[str, Any] | None:
        if item is None:
            return None
        mode = self.identifier_mode
        record = dict(item)
        if mode is not None:
            record = mode.reveal(record, item["principal_id"])
        return {"email": record.get("email") or "", "principal_id": item["principal_id"], "created_at": item["created_at"]}

    def _find_org_login(self, email: str) -> dict[str, Any] | None:
        mode = self.identifier_mode
        if mode is not None:
            for token in mode.candidates(email):
                found = self._org_login_by_stored_digest(token)
                if found is not None:
                    return found
        return self.org_logins.get(email_hash(email))

    def _org_login_by_stored_digest(self, digest: str) -> dict[str, Any] | None:
        item = self.org_logins.get(digest)
        if item is None:
            pointer = self.org_logins_by_hmac.get(digest)
            item = None if pointer is None else self.org_logins.get(pointer)
        return item

    def _store_org_login(self, digest: str, material: dict[str, Any], at: str, *, created: bool) -> None:
        current = self.org_logins.get(digest)
        record = {
            "email_hash": digest,
            "email": material.get("email", ""),
            "org_id": material["org_id"],
            "created_at": current["created_at"] if current is not None else at,
        }
        for key in ("email_hmac", "email_kid", "email_ciphertext"):
            if material.get(key):
                record[key] = material[key]
        self.org_logins[digest] = record
        if record.get("email_hmac"):
            self.org_logins_by_hmac[record["email_hmac"]] = digest

    def _copy_org_login(self, item: dict[str, Any] | None) -> dict[str, Any] | None:
        if item is None:
            return None
        mode = self.identifier_mode
        record = dict(item)
        if mode is not None:
            record = mode.reveal(record, item["org_id"])
        return {"email": record.get("email") or "", "org_id": item["org_id"], "created_at": item["created_at"]}

    def put_magic(self, record: dict[str, Any]) -> None:
        with self._lock:
            self.magic[record["token_hash"]] = dict(record)

    def get_magic(self, token_hash_value: str) -> dict[str, Any] | None:
        with self._lock:
            item = self.magic.get(token_hash_value)
            return dict(item) if item else None

    def consume_magic(self, token_hash_value: str, at: str) -> None:
        with self._lock:
            self.magic[token_hash_value]["used_at"] = at

    def put_session(self, record: dict[str, Any]) -> None:
        with self._lock:
            self.sessions[record["token_hash"]] = dict(record)

    def get_session(self, token_hash_value: str) -> dict[str, Any] | None:
        with self._lock:
            item = self.sessions.get(token_hash_value)
            return dict(item) if item else None

    def put_passkey(self, record: dict[str, Any]) -> None:
        with self._lock:
            self.passkeys[record["credential_id"]] = dict(record)

    def list_passkeys(self, principal_id: str) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(item) for item in self.passkeys.values() if item["principal_id"] == principal_id]

    def passkey_by_id(self, credential_id: str) -> dict[str, Any] | None:
        with self._lock:
            item = self.passkeys.get(credential_id)
            return dict(item) if item else None

    def delete_passkey(self, credential_id: str, principal_id: str) -> bool:
        with self._lock:
            item = self.passkeys.get(credential_id)
            if item is None or item["principal_id"] != principal_id:
                return False
            del self.passkeys[credential_id]
            return True

    def update_passkey_use(self, credential_id: str, sign_count: int, at: str) -> None:
        with self._lock:
            item = self.passkeys[credential_id]
            item["sign_count"] = sign_count
            item["last_used_at"] = at

    def put_challenge(self, record: dict[str, Any]) -> None:
        with self._lock:
            self.challenges[record["challenge_id"]] = dict(record)

    def take_challenge(
        self, kind: str, challenge: str, principal_id: str | None, origin: str, now: str
    ) -> dict[str, Any] | None:
        with self._lock:
            matches = [
                item
                for item in self.challenges.values()
                if item["kind"] == kind
                and item["challenge"] == challenge
                and item["origin"] == origin
                and not item.get("used_at")
                and item["expires_at"] >= now
                and item.get("principal_id") == principal_id
            ]
            if not matches:
                return None
            chosen = max(matches, key=lambda item: item["expires_at"])
            chosen["used_at"] = now
            return dict(chosen)

    def put_push(self, record: dict[str, Any]) -> None:
        with self._lock:
            self.push_devices[record["device_id"]] = dict(record)

    def list_push(self, principal_id: str) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(item) for item in self.push_devices.values() if item["principal_id"] == principal_id]

    def delete_push(self, device_id: str, principal_id: str) -> bool:
        with self._lock:
            item = self.push_devices.get(device_id)
            if item is None or item["principal_id"] != principal_id:
                return False
            del self.push_devices[device_id]
            return True

    def put_approval(self, record: dict[str, Any]) -> None:
        with self._lock:
            self.approvals[record["approval_id"]] = dict(record)

    def pending_approval(self, principal_id: str, action_hash: str, now: str) -> dict[str, Any] | None:
        with self._lock:
            for item in self.approvals.values():
                if (
                    item["principal_id"] == principal_id
                    and item["action_hash"] == action_hash
                    and item["status"] == "pending"
                    and not item.get("used_at")
                    and item["expires_at"] >= now
                ):
                    return dict(item)
            return None

    def list_approvals(self, principal_id: str) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(item) for item in self.approvals.values() if item["principal_id"] == principal_id]

    def get_approval(self, approval_id: str) -> dict[str, Any] | None:
        with self._lock:
            item = self.approvals.get(approval_id)
            return dict(item) if item else None

    def save_approval(self, record: dict[str, Any]) -> None:
        with self._lock:
            self.approvals[record["approval_id"]] = dict(record)

    def save_agent(self, record: dict[str, Any]) -> None:
        with self._lock:
            stamped = _stamp_env(record)
            key = _env_key(stamped["agent_id"])
            self.agents[key] = stamped
            self.by_fingerprint[_env_key(stamped["fingerprint"])] = key

    def get_agent(self, agent_id: str) -> dict[str, Any] | None:
        with self._lock:
            item = self.agents.get(_env_key(agent_id))
            return dict(item) if item else None

    def agent_by_fingerprint(self, fingerprint: str) -> dict[str, Any] | None:
        with self._lock:
            key = self.by_fingerprint.get(_env_key(fingerprint))
            if key is None:
                return None
            return dict(self.agents[key])

    def list_agents(self, *, operator_org_id: str | None = None, principal_id: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            rows = [item for item in self.agents.values() if _in_env(item)]
            if operator_org_id is not None:
                rows = [item for item in rows if item["operator_org_id"] == operator_org_id]
            if principal_id is not None:
                rows = [item for item in rows if item["principal_id"] == principal_id]
            return [dict(item) for item in rows]

    def save_agreement(self, record: dict[str, Any]) -> None:
        with self._lock:
            stamped = _stamp_env(record)
            self.agreements[stamped["agreement_id"]] = stamped

    def get_agreement(self, agreement_id: str) -> dict[str, Any] | None:
        with self._lock:
            item = self.agreements.get(agreement_id)
            if item is None or not _in_env(item):
                return None
            return dict(item)

    def list_agreements(self, agent_id: str) -> list[dict[str, Any]]:
        with self._lock:
            return [
                dict(item)
                for item in self.agreements.values()
                if item["agent_id"] == agent_id and _in_env(item)
            ]

    def add_report(self, record: dict[str, Any]) -> None:
        with self._lock:
            stamped = _stamp_env(record)
            for item in self.reports:
                if not _in_env(item):
                    continue
                if (
                    item["reporter_org_id"] == stamped["reporter_org_id"]
                    and item["agent_id"] == stamped["agent_id"]
                    and item["kind"] == stamped["kind"]
                    and item["evidence_hash"] == stamped["evidence_hash"]
                ):
                    raise BureauError(409, "duplicate report")
            self.reports.append(stamped)

    def reports_for_agent(self, agent_id: str) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(item) for item in self.reports if item["agent_id"] == agent_id and _in_env(item)]

    def reports_by_org_on_day(self, org_id: str, day: str) -> int:
        with self._lock:
            return sum(
                1
                for item in self.reports
                if _in_env(item) and item["reporter_org_id"] == org_id and item["created_at"].startswith(day)
            )

    def org_has_report(self, org_id: str) -> bool:
        with self._lock:
            return any(_in_env(item) and item["reporter_org_id"] == org_id for item in self.reports)

    def get_report(self, report_id: str) -> dict[str, Any] | None:
        with self._lock:
            for item in self.reports:
                if item["report_id"] == report_id and _in_env(item):
                    return dict(item)
            return None

    def set_report_excluded(self, report_id: str, excluded: bool) -> None:
        with self._lock:
            for item in self.reports:
                if item["report_id"] == report_id and _in_env(item):
                    item["excluded"] = excluded

    def all_reports(self) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(item) for item in self.reports if _in_env(item)]

    def org_directory(self) -> dict[str, dict[str, str]]:
        with self._lock:
            return {
                org_id: {"org_type": item["org_type"], "created_at": item["created_at"], "status": item["status"]}
                for org_id, item in self.orgs.items()
            }

    def add_interaction(self, record: dict[str, Any]) -> None:
        with self._lock:
            self.interactions.append(_stamp_env(record))

    def interactions_for_agent(self, agent_id: str) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(item) for item in self.interactions if item["agent_id"] == agent_id and _in_env(item)]

    def interactions_for_operator(self, operator_org_id: str) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(item) for item in self.interactions if item["operator_org_id"] == operator_org_id and _in_env(item)]

    def add_signal(self, record: dict[str, Any]) -> None:
        with self._lock:
            self.agent_signals.append(_stamp_env(record))

    def agent_ids_for_signal(self, kind: str, value: str) -> list[str]:
        with self._lock:
            return [
                item["agent_id"]
                for item in self.agent_signals
                if _in_env(item) and item["kind"] == kind and item["value"] == value
            ]

    def all_interactions(self) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(item) for item in self.interactions if _in_env(item)]

    def add_org_signal(self, record: dict[str, Any]) -> None:
        with self._lock:
            stamped = _stamp_env(record)
            for item in self.org_signals:
                if (
                    _in_env(item)
                    and item["org_id"] == stamped["org_id"]
                    and item["kind"] == stamped["kind"]
                    and item["value"] == stamped["value"]
                ):
                    return
            self.org_signals.append(stamped)

    def org_signal_groups(self) -> list[set[str]]:
        with self._lock:
            grouped: dict[str, set[str]] = {}
            for item in self.org_signals:
                if not _in_env(item):
                    continue
                grouped.setdefault(item["value"], set()).add(item["org_id"])
            return [members for members in grouped.values() if len(members) >= 2]

    def add_identity_link(self, record: dict[str, Any]) -> None:
        with self._lock:
            self.identity_links.append(_stamp_env(record))

    def links_for_agent(self, agent_id: str) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(item) for item in self.identity_links if item["agent_id"] == agent_id and _in_env(item)]

    def add_proofing(self, record: dict[str, Any]) -> None:
        with self._lock:
            stamped = _stamp_env(record)
            for item in self.proofings:
                if not _in_env(item):
                    continue
                if (
                    item["agent_id"] == stamped["agent_id"]
                    and item["method"] == stamped["method"]
                    and item["evidence_hash"] == stamped["evidence_hash"]
                ):
                    return
            self.proofings.append(stamped)

    def proofings_for_agent(self, agent_id: str) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(item) for item in self.proofings if item["agent_id"] == agent_id and _in_env(item)]

    def add_consortium_member(self, record: dict[str, Any]) -> None:
        with self._lock:
            self.consortium_members[record["org_id"]] = dict(record)

    def consortium_member_for_org(self, org_id: str) -> dict[str, Any] | None:
        with self._lock:
            item = self.consortium_members.get(org_id)
            return dict(item) if item else None

    def add_sighting(self, record: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            stamped = _stamp_env(record)
            for item in self.consortium_sightings:
                if _in_env(item) and item["member_id"] == stamped["member_id"] and item["fingerprint"] == stamped["fingerprint"]:
                    return dict(item)
            self.consortium_sightings.append(stamped)
            return dict(stamped)

    def sighting_member_ids(self, fingerprint: str) -> list[str]:
        with self._lock:
            return [item["member_id"] for item in self.consortium_sightings if _in_env(item) and item["fingerprint"] == fingerprint]

    def add_inquiry(self, record: dict[str, Any]) -> None:
        with self._lock:
            self.inquiries.append(_stamp_env(record))

    def inquiries_for_principal(self, principal_id: str) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(item) for item in self.inquiries if item["principal_id"] == principal_id and _in_env(item)]

    def add_subscription(self, record: dict[str, Any]) -> None:
        with self._lock:
            stamped = _stamp_env(record)
            for item in self.subscriptions:
                if (
                    _in_env(item)
                    and item["org_id"] == stamped["org_id"]
                    and item["agent_id"] == stamped["agent_id"]
                    and item["webhook_url"] == stamped["webhook_url"]
                ):
                    raise BureauError(409, "subscription already exists")
            self.subscriptions.append(stamped)

    def subscriptions_for_agent(self, agent_id: str) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(item) for item in self.subscriptions if item["agent_id"] == agent_id and _in_env(item)]

    def subscriptions_for_org(self, org_id: str) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(item) for item in self.subscriptions if item["org_id"] == org_id and _in_env(item)]

    def delete_subscription(self, subscription_id: str, org_id: str) -> bool:
        with self._lock:
            before = len(self.subscriptions)
            self.subscriptions = [
                item
                for item in self.subscriptions
                if not (_in_env(item) and item["subscription_id"] == subscription_id and item["org_id"] == org_id)
            ]
            return len(self.subscriptions) != before

    def add_alert(self, record: dict[str, Any]) -> None:
        with self._lock:
            self.alerts.append(_stamp_env(record))

    def alerts_for_org(self, org_id: str) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(item) for item in self.alerts if item["org_id"] == org_id and _in_env(item)]

    def get_subscription(self, subscription_id: str) -> dict[str, Any] | None:
        with self._lock:
            for item in self.subscriptions:
                if item["subscription_id"] == subscription_id:
                    return dict(item)
            return None

    def add_delivery(self, record: dict[str, Any]) -> None:
        with self._lock:
            self.deliveries.append(dict(record))

    def deliveries_for_org(self, org_id: str) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(item) for item in self.deliveries if item["org_id"] == org_id]

    def add_dispute(self, record: dict[str, Any]) -> None:
        with self._lock:
            self.disputes.append(_stamp_env(record))

    def list_disputes(self) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(item) for item in self.disputes if _in_env(item)]

    def disputes_for_principal(self, principal_id: str) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(item) for item in self.disputes if item["principal_id"] == principal_id and _in_env(item)]

    def get_dispute(self, dispute_id: str) -> dict[str, Any] | None:
        with self._lock:
            for item in self.disputes:
                if item["dispute_id"] == dispute_id and _in_env(item):
                    return dict(item)
            return None

    def save_dispute(self, record: dict[str, Any]) -> None:
        with self._lock:
            stamped = _stamp_env(record)
            for index, item in enumerate(self.disputes):
                if item["dispute_id"] == stamped["dispute_id"] and _in_env(item):
                    self.disputes[index] = stamped
                    return

    def reporter_types(self) -> dict[str, str]:
        with self._lock:
            return {org_id: item["org_type"] for org_id, item in self.orgs.items()}

    def append_consent(self, fields: dict[str, Any]) -> dict[str, Any]:
        from kata_service.consent import seal_event

        with self._lock:
            source_ref = str(fields.get("source_ref") or "")
            if source_ref:
                for item in self.consent_events:
                    if item.get("source_ref") == source_ref:
                        return dict(item)
            prev = self.consent_events[-1]["entry_hash"] if self.consent_events else None
            sealed = seal_event(prev, fields)
            self.consent_events.append(sealed)
            return dict(sealed)

    def list_consent(self, principal_id: str | None = None, purpose: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            rows = self.consent_events
            if principal_id is not None:
                rows = [item for item in rows if item["principal_id"] == principal_id]
            if purpose is not None:
                rows = [item for item in rows if item["purpose"] == purpose]
            return [dict(item) for item in rows]

    def delete_consent(self, event_id: str) -> None:
        raise BureauError(409, "gab_consent_events is append-only")

    def put_payload(self, record: dict[str, Any]) -> None:
        with self._lock:
            self.payloads[record["payload_id"]] = dict(record)

    def get_payload(self, payload_id: str) -> dict[str, Any] | None:
        with self._lock:
            item = self.payloads.get(payload_id)
            return dict(item) if item else None


class BureauService:
    def __init__(
        self,
        repo: MemoryRepo,
        *,
        now=None,
        log_store=None,
        log_key: PrivateKey | None = None,
        mailer: Mailer | None = None,
        sender: WebhookSender | None = None,
        magic_link_ttl_seconds: int = 900,
        session_ttl_seconds: int = 43200,
        report_daily_cap: int = 20,
        dev_mailbox: bool = False,
        public_base_url: str = "http://127.0.0.1:8765",
        policy: ScorePolicy | None = None,
        consortium_match_threshold: int = 2,
        deployment_env: str = "production",
        webhook_attempts: int = 4,
        webhook_base_delay: float = 0.5,
        webhook_sleep=None,
        step_up_approval: bool = False,
        approval_ttl_seconds: int = 300,
        vapid_public_key: str | None = None,
        vapid_private_key: str | None = None,
        vapid_subject: str | None = None,
        key_provider=None,
        keyed_identifiers: bool = False,
        hmac_rate_subject: bool = False,
        stop_plaintext_email: bool = False,
        consent_events: bool = False,
        consent_push: bool = False,
        consent_network: bool = False,
        entity_only: bool = False,
        network_step_up: bool = False,
        ledger_hygiene: bool = False,
        dek_store=None,
    ) -> None:
        self.repo = repo
        self.deployment_env = deployment_env if deployment_env in {"production", "sandbox"} else "production"
        self._now = now or (lambda: datetime.now(timezone.utc))
        self.log_store = log_store
        self.log_key = log_key
        self.mailer = mailer or ConsoleMailer()
        self.sender = sender or RecordingSender()
        self.magic_link_ttl_seconds = magic_link_ttl_seconds
        self.session_ttl_seconds = session_ttl_seconds
        self.report_daily_cap = report_daily_cap
        self.dev_mailbox_enabled = dev_mailbox
        self.public_base_url = public_base_url.rstrip("/")
        self.policy = policy or ScorePolicy()
        self.consortium_match_threshold = consortium_match_threshold
        self.webhook_attempts = webhook_attempts
        self.webhook_base_delay = webhook_base_delay
        self.webhook_sleep = webhook_sleep or time.sleep
        self.step_up_approval = step_up_approval
        self.approval_ttl_seconds = approval_ttl_seconds
        self.vapid_public_key = vapid_public_key
        self.vapid_private_key = vapid_private_key
        self.vapid_subject = vapid_subject
        self.key_provider = key_provider
        self.keyed_identifiers = keyed_identifiers
        self.hmac_rate_subject = hmac_rate_subject
        self.stop_plaintext_email = stop_plaintext_email
        self.consent_events_enabled = consent_events
        self.consent_push = consent_push
        self.consent_network = consent_network
        self.entity_only = entity_only
        self.network_step_up = network_step_up
        self.ledger_hygiene = ledger_hygiene
        self.dek_store = dek_store
        self._rate_purged_before: str | None = None
        if keyed_identifiers:
            from kata_service.identifiers import IdentifierMode

            self.repo.identifier_mode = IdentifierMode(key_provider, stop_plaintext=stop_plaintext_email)
        self.push_outbox: list[dict[str, str]] = []
        self.dev_mailbox: list[dict[str, str]] = []

    def now(self) -> datetime:
        current = self._now()
        if current.tzinfo is None:
            current = current.replace(tzinfo=timezone.utc)
        return current

    def stamp(self) -> str:
        return self.now().strftime("%Y-%m-%dT%H:%M:%SZ")

    def authenticate(self, token: str, *, admin_token: str | None) -> Auth:
        if not token:
            raise BureauError(401, "credentials are required")
        sandbox = self.deployment_env == "sandbox"
        if admin_token and hmac.compare_digest(token, admin_token):
            return Auth(admin=True, scopes=frozenset(SCOPES), kind="admin", key_id="admin", test=sandbox)
        key = self.repo.key_by_hash(token_hash(token))
        if key is not None:
            if key.get("revoked_at"):
                raise BureauError(401, "api key is revoked")
            token_says_test = token.startswith("gab_test_")
            record_says_test = _key_is_test("", key)
            if token_says_test != record_says_test:
                raise BureauError(401, "credentials are required")
            test_key = token_says_test
            if sandbox and not test_key:
                raise BureauError(403, "this deployment accepts test keys")
            return Auth(
                org_id=key["org_id"],
                key_id=key["key_id"],
                scopes=frozenset(key["scopes"]),
                kind="key",
                test=test_key or sandbox,
            )
        session = self.repo.get_session(token_hash(token))
        if session is not None:
            if session["expires_at"] < self.stamp():
                raise BureauError(401, "session expired")
            if session["kind"] == "portal":
                return Auth(principal_id=session["subject_id"], kind="portal", test=sandbox)
            org = self.repo.get_org(session["subject_id"])
            if org is None:
                raise BureauError(401, "session is not valid")
            return Auth(
                org_id=org["org_id"],
                scopes=frozenset(default_scopes(org["org_type"])),
                kind="org_session",
                test=sandbox,
            )
        raise BureauError(401, "credentials are required")

    def record_consent(self, auth: Auth, body: dict[str, Any]) -> dict[str, Any]:
        if not self.consent_events_enabled:
            raise BureauError(404, "consent events are off")
        self._portal(auth)
        purpose = str(body.get("purpose") or "")
        self._consent_purpose_enabled(purpose)
        granted = body.get("granted")
        if granted is not True and granted is not False:
            raise BureauError(400, "granted must be true or false")
        version = str(body.get("text_version") or "") or None
        return self._append_consent(auth.principal_id or "", purpose, bool(granted), text_version=version)

    def _consent_purpose_enabled(self, purpose: str) -> None:
        if purpose == "push" and self.consent_push:
            return
        if purpose == "network" and self.consent_network:
            return
        if purpose in {"push", "network"}:
            raise BureauError(404, f"{purpose} consent purpose is off")
        raise BureauError(400, "purpose is not push or network")

    def _append_consent(
        self,
        principal_id: str,
        purpose: str,
        granted: bool,
        *,
        text_version: str | None = None,
        source_ref: str | None = None,
    ) -> dict[str, Any]:
        from kata_service.consent import ConsentTextError, notice

        try:
            text = notice(purpose, text_version)
        except ConsentTextError as exc:
            raise BureauError(400, str(exc)) from exc
        return self.repo.append_consent(
            {
                "event_id": _id("cns"),
                "principal_id": principal_id,
                "purpose": purpose,
                "granted": granted,
                "text_version": text["text_version"],
                "text_sha256": text["text_sha256"],
                "at": self.stamp(),
                "source_ref": source_ref or "",
            }
        )

    def _require_network_consent(self, principal_id: str) -> None:
        if not self.consent_network:
            return
        rows = [item for item in self.repo.list_consent(principal_id, "network") if item.get("granted") is True]
        if not rows:
            raise BureauError(403, "network purpose needs a consent event")

    def hit_rate(self, subject: str) -> int:
        if self.hmac_rate_subject:
            cutoff = (self.now() - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M")
            if self._rate_purged_before != cutoff:
                self.repo.purge_rate(cutoff)
                self._rate_purged_before = cutoff
        window = self.now().strftime("%Y-%m-%dT%H:%M")
        return self.repo.hit_rate(subject, window)

    def create_org(self, auth: Auth, name: str, org_type: str, entity_kind_value: str | None = None) -> dict[str, Any]:
        self._admin(auth)
        if org_type not in ORG_TYPES:
            raise BureauError(400, "org_type is not a bureau participant type")
        name = _short(name, "name", 120)
        from kata_service.entity_mode import entity_kind as checked_kind

        record = {
            "org_id": _id("org"),
            "name": name,
            "org_type": org_type,
            "status": "active",
            "created_at": self.stamp(),
        }
        kind = checked_kind(entity_kind_value, required=self.entity_only)
        if kind:
            record["entity_kind"] = kind
        self.repo.create_org(record)
        return record

    def create_key(
        self,
        auth: Auth,
        org_id: str,
        name: str,
        scopes: list[str] | None,
        environment: str | None = None,
    ) -> dict[str, Any]:
        org = self._org(org_id)
        if not auth.admin and auth.org_id != org_id:
            raise BureauError(404, "organization was not found")
        self._scope(auth, "keys:manage")
        chosen = list(scopes or default_scopes(org["org_type"]))
        if any(item not in SCOPES for item in chosen):
            raise BureauError(400, "unknown scope")
        requested = str(environment or "").strip().lower()
        if requested and requested not in {"test", "live"}:
            raise BureauError(400, "environment must be test or live")
        if self.deployment_env == "sandbox" or auth.test:
            if requested == "live":
                raise BureauError(403, "this deployment issues test keys")
            requested = "test"
        elif not requested:
            requested = "live"
        token, prefix, digest = _new_key(test=requested == "test")
        record = {
            "key_id": _id("key"),
            "org_id": org_id,
            "name": _short(name, "name", 80),
            "prefix": prefix,
            "environment": requested,
            "secret_hash": digest,
            "scopes": chosen,
            "created_at": self.stamp(),
            "revoked_at": None,
            "rotated_from": None,
        }
        self.repo.create_key(record)
        public = _public_key(record)
        public["token"] = token
        return public

    def list_keys(self, auth: Auth, org_id: str) -> list[dict[str, Any]]:
        if not auth.admin and auth.org_id != org_id:
            raise BureauError(404, "organization was not found")
        self._scope(auth, "keys:manage")
        return [_public_key(item) for item in self.repo.list_keys(org_id)]

    def rotate_key(self, auth: Auth, key_id: str) -> dict[str, Any]:
        self._scope(auth, "keys:manage")
        current = self.repo.get_key(key_id)
        if current is None or (not auth.admin and current["org_id"] != auth.org_id):
            raise BureauError(404, "api key was not found")
        if current.get("revoked_at"):
            raise BureauError(400, "api key is already revoked")
        self.repo.revoke_key(key_id, self.stamp())
        environment = "test" if _key_is_test("", current) else "live"
        created = self.create_key(auth, current["org_id"], current["name"], list(current["scopes"]), environment)
        return created

    def register_org_email(self, auth: Auth, org_id: str, email: str) -> dict[str, str]:
        if not auth.admin and auth.org_id != org_id:
            raise BureauError(404, "organization was not found")
        self._scope(auth, "keys:manage")
        self._org(org_id)
        address = _email(email)
        self.repo.upsert_org_login(address, org_id, self.stamp())
        return {"registered": "true", "org_id": org_id}

    def score_model(self) -> dict[str, Any]:
        return self.policy.weights.public()

    def add_consortium_member(self, auth: Auth, org_id: str) -> dict[str, Any]:
        self._admin(auth)
        self._org(org_id)
        existing = self.repo.consortium_member_for_org(org_id)
        if existing is not None:
            return _public_member(existing)
        record = {
            "member_id": _id("cmb"),
            "org_id": org_id,
            "status": "active",
            "created_at": self.stamp(),
        }
        self.repo.add_consortium_member(record)
        return _public_member(record)

    def record_sighting(self, auth: Auth, fingerprint: str) -> dict[str, Any]:
        member = self._consortium_member(auth)
        fingerprint = _fingerprint(fingerprint)
        record = self.repo.add_sighting(
            {
                "sighting_id": _id("sgt"),
                "member_id": member["member_id"],
                "fingerprint": fingerprint,
                "seen_at": self.stamp(),
            }
        )
        return {"sighting_id": record["sighting_id"], "fingerprint": fingerprint, "seen_at": record["seen_at"]}

    def match_sightings(self, auth: Auth, fingerprint: str) -> dict[str, Any]:
        member = self._consortium_member(auth)
        fingerprint = _fingerprint(fingerprint)
        others = {item for item in self.repo.sighting_member_ids(fingerprint) if item != member["member_id"]}
        if len(others) >= self.consortium_match_threshold:
            return {"matched": True, "other_member_count": len(others)}
        return {"matched": False}

    def register_agent(self, auth: Auth, body: dict[str, Any]) -> dict[str, Any]:
        self._scope(auth, "registry:write")
        org = self._caller_org(auth)
        if org["org_type"] != "agent_operator":
            raise BureauError(403, "only an agent operator registers agents")
        agent_id = str(body.get("agent_id") or "")
        if not _AGENT_ID.match(agent_id):
            raise BureauError(400, "agent_id is missing or invalid")
        if self.repo.get_agent(agent_id) is not None:
            raise BureauError(409, "agent_id is already registered")
        try:
            public = public_key_from_jwk(body.get("public_key") or {})
        except (KataError, TypeError):
            raise BureauError(400, "public_key is not a usable JWK") from None
        if self.repo.agent_by_fingerprint(public.fingerprint) is not None:
            raise BureauError(409, "public key is already registered")
        level = str(body.get("verification_level") or "key_bound")
        if level not in OPERATOR_LEVELS:
            raise BureauError(400, "verification_level cannot be set by the operator")
        principal_id = str(body.get("principal_id") or _id("prn"))
        if not _AGENT_ID.match(principal_id):
            raise BureauError(400, "principal_id is invalid")
        at = self.stamp()
        self.repo.ensure_principal(principal_id, at)
        if body.get("principal_email"):
            if self.entity_only:
                raise BureauError(400, "personal email is not accepted")
            self._bind_principal_email(str(body.get("principal_email")), principal_id, at)
        record = {
            "agent_id": agent_id,
            "operator_org_id": org["org_id"],
            "principal_id": principal_id,
            "status": "active",
            "verification_level": level,
            "algorithm": public.algorithm,
            "fingerprint": public.fingerprint,
            "public_key": public.to_jwk(),
            "created_at": at,
            "updated_at": at,
            "score": 0,
            "score_reasons": [],
            "cold_start": True,
            "principal_public_key": None,
        }
        from kata_service.entity_mode import entity_kind as checked_kind

        kind = checked_kind(body.get("entity_kind"), required=self.entity_only)
        if kind:
            record["entity_kind"] = kind
        if self.consent_network and _registration_signals(body):
            self._require_network_consent(principal_id)
        links = self._link_denied_identity(record, body, at)
        self._record_proof(record["agent_id"], org["org_id"], "key_binding", public.fingerprint, at)
        review = str(body.get("proofing_evidence") or "").strip()
        if review:
            if not _EVIDENCE.match(review):
                raise BureauError(400, "proofing_evidence must be sha256 and 64 hex characters")
            self._record_proof(record["agent_id"], org["org_id"], "operator_review", review, at)
        self._rescore(record)
        self.repo.save_agent(record)
        self._log(
            "registration",
            {
                "agent_id": agent_id,
                "fingerprint": public.fingerprint,
                "record_hash": hash_document({"agent_id": agent_id, "fingerprint": public.fingerprint, "status": "active"}),
                "status": "active",
            },
        )
        view = self._agent_view(auth, record)
        if links:
            applied = next((item["points"] for item in record.get("score_reasons") or [] if item["code"] == "IDENTITY_LINK"), 0)
            view["identity_link"] = {"linked_agent_ids": links, "penalty": abs(int(applied))}
        return view

    def attest_agent(self, auth: Auth, agent_id: str) -> dict[str, Any]:
        self._scope(auth, "registry:write")
        org = self._caller_org(auth)
        if org["org_type"] not in {"wallet", "bank_issuer"}:
            raise BureauError(403, "only a wallet or bank can attest an agent")
        agent = self._agent(agent_id)
        agent["verification_level"] = "institution_attested"
        agent["updated_at"] = self.stamp()
        self._rescore(agent)
        self.repo.save_agent(agent)
        return self._agent_view(auth, agent)

    def submit_proofing(self, auth: Auth, agent_id: str, body: dict[str, Any]) -> dict[str, Any]:
        self._scope(auth, "registry:write")
        org = self._caller_org(auth)
        agent = self._agent(agent_id)
        method = str(body.get("method") or "")
        if method not in {"operator_review", "institution_attestation"}:
            raise BureauError(400, "method is not operator_review or institution_attestation")
        if method == "operator_review" and org["org_id"] != agent["operator_org_id"]:
            raise BureauError(403, "only the operator can file an operator review")
        if method == "institution_attestation" and org["org_type"] not in {"wallet", "bank_issuer"}:
            raise BureauError(403, "only a wallet or bank can file an institution attestation")
        evidence = str(body.get("evidence_hash") or "")
        if not _EVIDENCE.match(evidence):
            raise BureauError(400, "evidence_hash must be sha256 and 64 hex characters")
        record = self._record_proof(agent_id, org["org_id"], method, evidence, self.stamp())
        self._rescore(agent)
        self.repo.save_agent(agent)
        view = self._agent_view(auth, agent)
        view["proofing"] = _public_proof(record)
        return view

    def set_status(
        self,
        auth: Auth,
        agent_id: str,
        status: str,
        assertion: dict[str, Any] | None = None,
        origin: str | None = None,
    ) -> dict[str, Any]:
        if status not in AGENT_STATUSES:
            raise BureauError(400, "status is not active, suspended, or revoked")
        agent = self._agent(agent_id)
        if not auth.admin and auth.org_id != agent["operator_org_id"] and auth.principal_id != agent["principal_id"]:
            raise BureauError(404, "agent was not found")
        if auth.principal_id and status != "revoked":
            raise BureauError(403, "a principal can revoke the agent")
        if auth.principal_id and not auth.admin and not auth.org_id:
            from kata_service.portal_devices import require_assertion

            require_assertion(self, auth, assertion, origin or "")
        if not auth.admin and auth.principal_id is None:
            self._scope(auth, "registry:write")
        previous = agent["status"]
        agent["status"] = status
        agent["updated_at"] = self.stamp()
        self._rescore(agent)
        self.repo.save_agent(agent)
        if status == "revoked" and previous != "revoked":
            self._log(
                "revocation",
                {
                    "agent_id": agent_id,
                    "fingerprint": agent["fingerprint"],
                    "record_hash": hash_document({"agent_id": agent_id, "status": "revoked"}),
                    "status": "revoked",
                },
            )
            self._alert(agent, "revocation", {"status": "revoked"})
        view = self._agent_view(auth, agent)
        if auth.principal_id and not auth.admin and not auth.org_id:
            from kata_service.portal_devices import individual_view

            return individual_view(view)
        return view

    def get_agent(self, auth: Auth, agent_id: str) -> dict[str, Any]:
        self._scope(auth, "registry:read")
        return self._agent_view(auth, self._agent(agent_id))

    def lookup_fingerprint(self, auth: Auth, fingerprint: str) -> dict[str, Any]:
        self._scope(auth, "registry:read")
        agent = self.repo.agent_by_fingerprint(fingerprint)
        if agent is None:
            raise BureauError(404, "agent was not found")
        return self._agent_view(auth, agent)

    def store_intent(self, auth: Auth, agent_id: str, document: dict[str, Any]) -> dict[str, Any]:
        self._scope(auth, "registry:write")
        agent = self._agent(agent_id)
        if not auth.admin and auth.org_id != agent["operator_org_id"]:
            raise BureauError(404, "agent was not found")
        try:
            agreement = Agreement.from_dict(document)
        except (KataError, TypeError, ValueError):
            raise BureauError(400, "agreement document is not valid") from None
        if agreement.status not in {"active", "accepted"}:
            raise BureauError(400, "agreement is not active")
        for mandate in agreement.mandates:
            embedded = (mandate.get("agent") or {}).get("agent_id")
            if embedded != agent_id:
                raise BureauError(400, "agreement agent does not match the registry")
            principal_id = (mandate.get("principal") or {}).get("id")
            if principal_id != agent["principal_id"]:
                raise BureauError(400, "agreement principal does not match the registry")
            jwk = (mandate.get("agent") or {}).get("public_key")
            try:
                if public_key_from_jwk(jwk).fingerprint != agent["fingerprint"]:
                    raise BureauError(400, "agreement key does not match the registry")
            except (KataError, TypeError):
                raise BureauError(400, "agreement key does not match the registry") from None
        principal_jwk = _principal_jwk(agreement)
        bound = agent.get("principal_public_key")
        if bound and public_key_from_jwk(bound).fingerprint != public_key_from_jwk(principal_jwk).fingerprint:
            raise BureauError(400, "agreement principal key does not match the registry")
        agent["principal_public_key"] = principal_jwk
        self.repo.save_agent(agent)
        at = self.stamp()
        record = {
            "agreement_id": agreement.agreement_id,
            "agent_id": agent_id,
            "document": agreement.to_dict(),
            "status": "active",
            "updated_at": at,
        }
        self.repo.save_agreement(record)
        return _agreement_summary(record)

    def list_intents(self, auth: Auth, agent_id: str) -> list[dict[str, Any]]:
        self._scope(auth, "registry:read")
        self._agent(agent_id)
        return [_agreement_summary(item) for item in self.repo.list_agreements(agent_id)]

    def verify(self, auth: Auth, body: dict[str, Any]) -> dict[str, Any]:
        self._scope(auth, "verify")
        reject_deep_json(body)
        self._screen("verify", body)
        agent_id = str(body.get("agent_id") or "")
        agent = self._agent(agent_id)
        action = body.get("action")
        if not isinstance(action, dict):
            raise BureauError(400, "action must be an object")
        if agent["status"] != "active":
            return self._present_verify(agent, action, {"verdict": "DENY", "kata_decision": "BLOCK", "reasons": ["AGENT_NOT_ACTIVE"], "messages": ["Agent is not active."], "agent_id": agent_id})
        active = [item for item in self.repo.list_agreements(agent_id) if item["status"] == "active"]
        chosen_id = body.get("agreement_id")
        if chosen_id:
            active = [item for item in active if item["agreement_id"] == chosen_id]
        if not active:
            return self._present_verify(agent, action, {"verdict": "DENY", "kata_decision": "BLOCK", "reasons": ["NO_ACTIVE_AGREEMENT"], "messages": ["No active agreement is stored."], "agent_id": agent_id})
        if len(active) > 1 and not chosen_id:
            return self._present_verify(
                agent,
                action,
                {
                    "verdict": "STEP_UP",
                    "kata_decision": "STEP_UP",
                    "reasons": ["AGREEMENT_NOT_SELECTED"],
                    "messages": ["More than one active agreement is stored."],
                    "agent_id": agent_id,
                },
            )
        record = active[0]
        agreement = Agreement.from_dict(record["document"])
        at = self.stamp()
        from kata_intent import evaluate

        principal_key = None
        if agent.get("principal_public_key"):
            principal_key = public_key_from_jwk(agent["principal_public_key"])
        try:
            result = evaluate(
                agreement,
                action,
                principal_public_key=principal_key,
                agent_id=agent_id,
                agent_public_key=public_key_from_jwk(agent["public_key"]),
                now=at,
                intent_id=body.get("intent_id"),
                ledger_sequence=agreement.ledger_sequence,
                ledger_head=agreement.ledger_head,
                ledger_as_of=at,
            )
        except KataError as exc:
            raise BureauError(400, str(exc)) from exc
        if result.verdict == "ALLOW":
            reason = self._velocity_reason(agent, action, at)
            if reason:
                payload = result.to_dict()
                payload["verdict"] = "DENY"
                payload["kata_decision"] = "BLOCK"
                payload["reasons"] = [*list(payload.get("reasons") or []), reason]
                payload["messages"] = [
                    *list(payload.get("messages") or []),
                    "The bureau velocity window for this agent or operator is exceeded.",
                ]
                payload["agent_id"] = agent_id
                payload["agreement_id"] = record["agreement_id"]
                return self._present_verify(agent, action, payload)
            try:
                agreement.record_allowed(action, at=at, intent_id=body.get("intent_id"))
            except KataError as exc:
                raise BureauError(400, str(exc)) from exc
            record["document"] = agreement.to_dict()
            record["updated_at"] = at
            self.repo.save_agreement(record)
            self._record_interaction(agent, auth, body, action, record["agreement_id"], at)
        payload = result.to_dict()
        payload["agent_id"] = agent_id
        payload["agreement_id"] = record["agreement_id"]
        return self._present_verify(agent, action, payload)

    def verify_checkout(self, auth: Auth, body: dict[str, Any]) -> dict[str, Any]:
        """Check a UCP checkout as an action. Sandbox test keys only."""

        reject_deep_json(body)
        self._scope(auth, "verify")
        if auth.kind != "key" or not auth.test:
            raise BureauError(403, "this route accepts test keys")
        version = str(body.get("version") or "")
        if version != "2026-08-25":
            raise BureauError(400, "version must be 2026-08-25")
        checkout = body.get("checkout")
        if not isinstance(checkout, dict):
            raise BureauError(400, "checkout must be an object")
        if self.entity_only:
            from kata_service.entity_mode import reject_contact_text

            reject_contact_text(checkout)
        from kata_service.ucp_checkout import CheckoutRejected, translate_checkout

        try:
            translated = translate_checkout(checkout, at=self.stamp())
        except CheckoutRejected as exc:
            raise BureauError(exc.status, exc.message) from exc
        agent_id = str(body.get("agent_id") or "")
        agent = self._agent(agent_id)
        extra = {
            "trust_score": {
                "score": agent.get("score"),
                "risk": self.policy.weights.risk(int(agent.get("score") or 0)),
                "model_version": self.policy.weights.model_version,
                "cold_start": agent.get("cold_start"),
            },
            "revocations": _checkout_revocations(self, agent),
            "ucp": translated.report,
        }
        if translated.deny_code:
            return {
                "verdict": "DENY",
                "kata_decision": "BLOCK",
                "reasons": [translated.deny_code],
                "messages": [translated.deny_message],
                "agent_id": agent_id,
                **extra,
            }
        forwarded: dict[str, Any] = {"agent_id": agent_id, "action": translated.action}
        if body.get("agreement_id"):
            forwarded["agreement_id"] = body.get("agreement_id")
        if body.get("intent_id"):
            forwarded["intent_id"] = body.get("intent_id")
        outcome = self.verify(auth, forwarded)
        outcome.update(extra)
        return outcome

    def report(self, auth: Auth, body: dict[str, Any]) -> dict[str, Any]:
        self._scope(auth, "report")
        reject_deep_json(body)
        self._screen("report", body)
        org = self._caller_org(auth)
        agent = self._agent(str(body.get("agent_id") or ""))
        kind = str(body.get("kind") or "")
        if kind not in REPORT_KINDS:
            raise BureauError(400, "kind is not a report type")
        evidence = str(body.get("evidence_hash") or "")
        if not _EVIDENCE.match(evidence):
            raise BureauError(400, "evidence_hash must be sha256 and 64 hex characters")
        summary = _short(str(body.get("summary") or ""), "summary", 500)
        outcome = body.get("outcome")
        if outcome is not None and outcome not in {"settled", "loss", "cleared"}:
            raise BureauError(400, "outcome is not settled, loss, or cleared")
        day = self.stamp()[:10]
        if self.repo.reports_by_org_on_day(org["org_id"], day) >= self.report_daily_cap:
            raise BureauError(429, "daily report cap reached")
        action_id = str(body.get("action_id") or "").strip() or None
        if action_id and not _AGENT_ID.match(action_id):
            raise BureauError(400, "action_id is invalid")
        record = {
            "report_id": _id("rpt"),
            "agent_id": agent["agent_id"],
            "reporter_org_id": org["org_id"],
            "kind": kind,
            "evidence_hash": evidence,
            "summary": summary,
            "outcome": outcome,
            "action_id": action_id,
            "created_at": self.stamp(),
            "excluded": False,
        }
        if self.policy.require_transaction_link and not self._report_counts(agent, record):
            raise BureauError(400, "a report requires an allowed verify with this agent that meets the link minimum")
        record["counts"] = True
        shared = str(body.get("shared_signal") or "").strip()
        if shared:
            self._require_network_consent(str(agent.get("principal_id") or ""))
            self.repo.add_org_signal(
                {
                    "org_id": org["org_id"],
                    "kind": "shared",
                    "value": _short(shared, "shared_signal", 128),
                    "created_at": self.stamp(),
                }
            )
        self.repo.add_report(record)
        self._log(
            "incident",
            {
                "agent_id": agent["agent_id"],
                "report_id": record["report_id"],
                "kind": kind,
                "evidence_hash": evidence,
                "record_hash": hash_document({"report_id": record["report_id"], "evidence_hash": evidence, "kind": kind}),
            },
        )
        before = agent.get("score", 0)
        self._rescore(agent)
        self.repo.save_agent(agent)
        self._alert(agent, "incident", {"report_id": record["report_id"], "kind": kind, "evidence_hash": evidence})
        if before - agent["score"] >= 50:
            self._alert(agent, "score_drop", {"previous_score": before, "score": agent["score"]})
        if kind == "transaction_outcome" and outcome == "settled" and self.policy.ring_detection:
            self._rescore_ring_peers(agent, org["org_id"])
        return _public_report(record, full=True)

    def list_reports(self, auth: Auth, agent_id: str) -> dict[str, Any]:
        self._scope(auth, "report")
        agent = self._agent(agent_id)
        reports = self.repo.reports_for_agent(agent_id)
        full = auth.admin or auth.org_id == agent["operator_org_id"] or self.repo.org_has_report(auth.org_id or "")
        counts: dict[str, int] = {kind: 0 for kind in REPORT_KINDS}
        for item in reports:
            if not item.get("excluded"):
                counts[item["kind"]] = counts.get(item["kind"], 0) + 1
        body: dict[str, Any] = {"agent_id": agent_id, "counts": counts, "contributor": full}
        if full:
            body["reports"] = [_public_report(self._annotate(agent, item), full=True) for item in reports]
        return body

    def inquire(self, auth: Auth, body: dict[str, Any]) -> dict[str, Any]:
        self._scope(auth, "inquire")
        reject_deep_json(body)
        purpose = str(body.get("purpose_code") or "")
        if purpose not in PURPOSE_CODES:
            raise BureauError(400, "purpose_code is required")
        agent = self._agent(str(body.get("agent_id") or ""))
        org = self._caller_org(auth)
        inquiry = {
            "inquiry_id": _id("inq"),
            "org_id": org["org_id"],
            "agent_id": agent["agent_id"],
            "principal_id": agent["principal_id"],
            "purpose_code": purpose,
            "at": self.stamp(),
        }
        self.repo.add_inquiry(inquiry)
        reports = self.repo.reports_for_agent(agent["agent_id"])
        counts: dict[str, int] = {kind: 0 for kind in REPORT_KINDS}
        for item in reports:
            if not item.get("excluded"):
                counts[item["kind"]] = counts.get(item["kind"], 0) + 1
        contributor = self.repo.org_has_report(org["org_id"])
        revocations = []
        if agent["status"] == "revoked":
            revocations.append({"kind": "agent", "id": agent["agent_id"], "at": agent["updated_at"]})
        for agreement in self.repo.list_agreements(agent["agent_id"]):
            if agreement["status"] == "revoked":
                revocations.append({"kind": "agreement", "id": agreement["agreement_id"], "at": agreement["updated_at"]})
        result = {
            "inquiry_id": inquiry["inquiry_id"],
            "purpose_code": purpose,
            "agent": {
                "agent_id": agent["agent_id"],
                "status": agent["status"],
                "verification_level": agent["verification_level"],
                "assurance_level": self._assurance(agent),
                "fingerprint": agent["fingerprint"],
                "algorithm": agent["algorithm"],
                "operator_name": org_name(self.repo, agent["operator_org_id"]),
                "operator_type": "agent_operator",
            },
            "authorizations": [_agreement_summary(item) for item in self.repo.list_agreements(agent["agent_id"]) if item["status"] == "active"],
            "revocations": revocations,
            "incidents": {"counts": counts},
            "trust_score": {
                "score": agent["score"],
                "risk": self.policy.weights.risk(int(agent.get("score") or 0)),
                "model_version": self.policy.weights.model_version,
                "reasons": agent["score_reasons"],
                "cold_start": agent["cold_start"],
            },
        }
        if contributor:
            result["incidents"]["recent"] = [
                {"report_id": item["report_id"], "kind": item["kind"], "evidence_hash": item["evidence_hash"], "created_at": item["created_at"]}
                for item in reports
            ]
        return result

    def subscribe(self, auth: Auth, agent_id: str, webhook_url: str) -> dict[str, Any]:
        self._scope(auth, "alerts")
        self._agent(agent_id)
        url = _webhook(webhook_url)
        record = {
            "subscription_id": _id("sub"),
            "org_id": auth.org_id,
            "agent_id": agent_id,
            "webhook_url": url,
            "created_at": self.stamp(),
        }
        self.repo.add_subscription(record)
        return record

    def list_subscriptions(self, auth: Auth) -> list[dict[str, Any]]:
        self._scope(auth, "alerts")
        return self.repo.subscriptions_for_org(auth.org_id or "")

    def unsubscribe(self, auth: Auth, subscription_id: str) -> dict[str, bool]:
        self._scope(auth, "alerts")
        if not self.repo.delete_subscription(subscription_id, auth.org_id or ""):
            raise BureauError(404, "subscription was not found")
        return {"deleted": True}

    def list_alerts(self, auth: Auth) -> list[dict[str, Any]]:
        self._scope(auth, "alerts")
        return self.repo.alerts_for_org(auth.org_id or "")

    def list_deliveries(self, auth: Auth) -> list[dict[str, Any]]:
        self._scope(auth, "alerts")
        return [_public_delivery(item) for item in self.repo.deliveries_for_org(auth.org_id or "")]

    def test_webhook(self, auth: Auth, subscription_id: str) -> dict[str, Any]:
        """Fire one signed test alert at a subscription this organization already owns."""

        self._scope(auth, "alerts")
        sub = self.repo.get_subscription(subscription_id)
        if sub is None or sub["org_id"] != (auth.org_id or ""):
            raise BureauError(404, "subscription was not found")
        at = self.stamp()
        alert = {
            "alert_id": _id("alt"),
            "agent_id": sub["agent_id"],
            "kind": "test",
            "score": None,
            "note": "test delivery",
        }
        document = {"alert": alert, "at": at, "kata_bureau_alert": "1"}
        body = dict(document)
        if self.log_key is not None:
            body["signature"] = sign_jws(document, self.log_key, typ=ALERT_TYP)
        delivered = self._deliver(
            org_id=sub["org_id"],
            agent_id=sub["agent_id"],
            alert_id=alert["alert_id"],
            url=sub["webhook_url"],
            body=body,
        )
        self.repo.add_alert(
            {
                "alert_id": alert["alert_id"],
                "org_id": sub["org_id"],
                "agent_id": sub["agent_id"],
                "kind": "test",
                "document": body,
                "created_at": at,
                "delivered": delivered,
            }
        )
        return {"alert_id": alert["alert_id"], "delivered": delivered, "kind": "test"}

    def list_audit(self, auth: Auth) -> list[dict[str, Any]]:
        self._scope(auth, "keys:manage")
        org_id = None if auth.admin else auth.org_id
        environment = "test" if auth.test else "live"
        return self.repo.list_audit(org_id, environment)

    def request_portal_link(self, email: str) -> dict[str, bool]:
        address = _email(email)
        at = self.stamp()
        existing = self.repo.login_by_email(address)
        if existing is None:
            principal_id = _id("prn")
            self.repo.ensure_principal(principal_id, at)
            self.repo.insert_login(address, principal_id, at)
        self._send_link("portal", address, email_hash(address))
        return {"sent": True}

    def _bind_principal_email(self, email: str, principal_id: str, at: str) -> None:
        address = _email(email)
        if self.repo.insert_login(address, principal_id, at) == "conflict":
            raise BureauError(409, "email is already bound to another principal")

    def request_org_link(self, email: str) -> dict[str, bool]:
        address = _email(email)
        login = self.repo.org_login_by_email(address)
        if login is not None:
            self._send_link("org", address, email_hash(address))
        return {"sent": True}

    def consume_link(self, token: str) -> dict[str, str]:
        record = self.repo.get_magic(token_hash(token))
        if record is None or record.get("used_at") or record["expires_at"] < self.stamp():
            raise BureauError(401, "magic link is not valid")
        self.repo.consume_magic(record["token_hash"], self.stamp())
        if record["kind"] == "portal":
            login = self.repo.login_by_subject(record.get("subject_hmac"), record["subject_hash"])
            if login is None:
                raise BureauError(401, "magic link is not valid")
            session = self._session("portal", login["principal_id"])
            return {"token": session, "kind": "portal", "principal_id": login["principal_id"]}
        login = self.repo.org_login_by_subject(record.get("subject_hmac"), record["subject_hash"])
        if login is None:
            raise BureauError(401, "magic link is not valid")
        session = self._session("org", login["org_id"])
        return {"token": session, "kind": "org", "org_id": login["org_id"]}

    def portal_agents(self, auth: Auth) -> list[dict[str, Any]]:
        self._portal(auth)
        from kata_service.portal_devices import individual_view

        return [individual_view(self._agent_view(auth, item)) for item in self.repo.list_agents(principal_id=auth.principal_id)]

    def portal_authorizations(self, auth: Auth, agent_id: str) -> list[dict[str, Any]]:
        self._portal(auth)
        agent = self._owned(auth, agent_id)
        return [_agreement_summary(item) for item in self.repo.list_agreements(agent["agent_id"])]

    def portal_reports(self, auth: Auth, agent_id: str) -> list[dict[str, Any]]:
        self._portal(auth)
        agent = self._owned(auth, agent_id)
        return [_public_report(self._annotate(agent, item), full=True) for item in self.repo.reports_for_agent(agent["agent_id"])]

    def portal_inquiries(self, auth: Auth) -> list[dict[str, Any]]:
        self._portal(auth)
        rows = []
        for item in self.repo.inquiries_for_principal(auth.principal_id or ""):
            org = self.repo.get_org(item["org_id"])
            rows.append(
                {
                    "inquiry_id": item["inquiry_id"],
                    "at": item["at"],
                    "agent_id": item["agent_id"],
                    "purpose_code": item["purpose_code"],
                    "organization": None if org is None else org["name"],
                    "org_type": None if org is None else org["org_type"],
                }
            )
        return rows

    def portal_revoke_agreement(
        self, auth: Auth, agreement_id: str, assertion: dict[str, Any] | None = None, origin: str | None = None
    ) -> dict[str, Any]:
        self._portal(auth)
        from kata_service.portal_devices import require_assertion

        require_assertion(self, auth, assertion, origin or "")
        record = self.repo.get_agreement(agreement_id)
        if record is None:
            raise BureauError(404, "agreement was not found")
        self._owned(auth, record["agent_id"])
        record["status"] = "revoked"
        record["updated_at"] = self.stamp()
        self.repo.save_agreement(record)
        self._log(
            "revocation",
            {
                "agent_id": record["agent_id"],
                "agreement_id": agreement_id,
                "record_hash": hash_document({"agreement_id": agreement_id, "status": "revoked"}),
                "status": "revoked",
            },
        )
        return _agreement_summary(record)

    def file_dispute(
        self,
        auth: Auth,
        report_id: str,
        statement: str,
        assertion: dict[str, Any] | None = None,
        origin: str | None = None,
    ) -> dict[str, Any]:
        self._portal(auth)
        from kata_service.portal_devices import require_assertion

        require_assertion(self, auth, assertion, origin or "")
        self._screen("dispute", {"report_id": report_id, "statement": statement, **({} if assertion is None else {"assertion": assertion})})
        report = self.repo.get_report(report_id)
        if report is None:
            raise BureauError(404, "report was not found")
        self._owned(auth, report["agent_id"])
        record = {
            "dispute_id": _id("dsp"),
            "report_id": report_id,
            "principal_id": auth.principal_id,
            "statement": _short(statement, "statement", 1000),
            "status": "open",
            "outcome": None,
            "created_at": self.stamp(),
            "updated_at": self.stamp(),
        }
        self.repo.add_dispute(record)
        report = self.repo.get_report(report_id)
        if report is not None:
            agent = self._agent(report["agent_id"])
            self._rescore(agent)
            self.repo.save_agent(agent)
        return record

    def portal_disputes(self, auth: Auth) -> list[dict[str, Any]]:
        self._portal(auth)
        return self.repo.disputes_for_principal(auth.principal_id or "")

    def admin_disputes(self, auth: Auth) -> list[dict[str, Any]]:
        self._admin(auth)
        return self.repo.list_disputes()

    def review_dispute(self, auth: Auth, dispute_id: str, status: str, outcome: str | None) -> dict[str, Any]:
        self._admin(auth)
        if status not in DISPUTE_STATUSES:
            raise BureauError(400, "status is not a dispute status")
        if status == "resolved" and outcome not in DISPUTE_OUTCOMES:
            raise BureauError(400, "resolved disputes need an outcome")
        if status != "resolved":
            outcome = None
        record = self.repo.get_dispute(dispute_id)
        if record is None:
            raise BureauError(404, "dispute was not found")
        record["status"] = status
        record["outcome"] = outcome
        record["updated_at"] = self.stamp()
        self.repo.save_dispute(record)
        report = self.repo.get_report(record["report_id"])
        if report is not None:
            excluded = status == "resolved" and outcome == "upheld"
            self.repo.set_report_excluded(report["report_id"], excluded)
            agent = self._agent(report["agent_id"])
            self._rescore(agent)
            self.repo.save_agent(agent)
        return record

    def latest_dev_link(self) -> dict[str, str]:
        if not self.dev_mailbox_enabled or not self.dev_mailbox:
            raise BureauError(404, "development mailbox is empty")
        return dict(self.dev_mailbox[-1])

    def _send_link(self, kind: str, email: str, subject_hash: str) -> None:
        token = secrets.token_urlsafe(32)
        expires = (self.now() + timedelta(seconds=self.magic_link_ttl_seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")
        record = {"token_hash": token_hash(token), "kind": kind, "subject_hash": subject_hash, "expires_at": expires, "used_at": None}
        mode = getattr(self.repo, "identifier_mode", None)
        if mode is not None:
            hmac_token = mode.provider.hmac(normalize_email(email), purpose="identifier")
            record["subject_hmac"] = hmac_token.encode()
            record["subject_kid"] = hmac_token.kid
            if mode.stop_plaintext:
                record["subject_hash"] = hmac_token.encode()
        self.repo.put_magic(record)
        path = "/portal" if kind == "portal" else "/dashboard"
        url = f"{self.public_base_url}{path}#token={token}"
        self.mailer.send_magic_link(email, url)
        if self.dev_mailbox_enabled:
            self.dev_mailbox.append({"kind": kind, "email": email, "url": url, "token": token})

    def _session(self, kind: str, subject_id: str) -> str:
        token = "gab_sess_" + secrets.token_urlsafe(24)
        expires = (self.now() + timedelta(seconds=self.session_ttl_seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.repo.put_session({"token_hash": token_hash(token), "kind": kind, "subject_id": subject_id, "expires_at": expires})
        return token

    def _rescore_ring_peers(self, agent: dict[str, Any], reporter_org_id: str) -> None:
        involved = {reporter_org_id, agent["operator_org_id"]}
        for source, target in self._discounted_edges():
            involved.add(source)
            involved.add(target)
        seen = {agent["agent_id"]}
        rescored = 0
        for other in self.repo.list_agents():
            if other["agent_id"] in seen or other["operator_org_id"] not in involved:
                continue
            seen.add(other["agent_id"])
            previous = other.get("score", 0)
            self._rescore(other)
            self.repo.save_agent(other)
            rescored += 1
            if previous - other["score"] >= 50:
                self._alert(other, "score_drop", {"previous_score": previous, "score": other["score"]})
            if rescored >= 200:
                break

    def _rescore(self, agent: dict[str, Any]) -> None:
        operator = self.repo.get_org(agent["operator_org_id"])
        reports = self.repo.reports_for_agent(agent["agent_id"])
        disputes = [item for item in self.repo.list_disputes() if any(item["report_id"] == report["report_id"] for report in reports)]
        assurance = self._assurance(agent)
        agent["assurance_level"] = assurance
        scored = trust_score(
            verification_level=assurance,
            operator_status="active" if operator and operator["status"] == "active" else "inactive",
            operator_org_id=agent["operator_org_id"],
            reports=reports,
            disputes=disputes,
            reporter_types=self.repo.reporter_types(),
            policy=self.policy,
            context=self._score_context(agent),
        )
        agent["score"] = scored["score"]
        agent["score_reasons"] = scored["reasons"]
        agent["cold_start"] = scored["cold_start"]

    def _score_context(self, agent: dict[str, Any]) -> ScoreContext:
        directory = self.repo.org_directory()
        all_reports = self.repo.all_reports()
        report_by_id = {item["report_id"]: item for item in all_reports}
        upheld: dict[str, int] = {}
        open_ids: set[str] = set()
        for item in self.repo.list_disputes():
            source = report_by_id.get(item["report_id"])
            if source is None:
                continue
            if item.get("status") == "resolved" and item.get("outcome") == "upheld":
                upheld[source["reporter_org_id"]] = upheld.get(source["reporter_org_id"], 0) + 1
            elif item.get("status") in {"open", "under_review"}:
                open_ids.add(item["report_id"])
        interactions = self.repo.interactions_for_agent(agent["agent_id"])
        linked: set[str] = set()
        actions: dict[str, set[str]] = {}
        for item in interactions:
            linked.add(item["counterparty_org_id"])
            actions.setdefault(item["counterparty_org_id"], set()).add(item["action_id"])
        external: dict[str, float] = {}
        for item in interactions:
            party = item["counterparty_org_id"]
            if party == agent["operator_org_id"]:
                continue
            raw = item.get("amount")
            amount = 0.0 if raw in (None, "") else float(raw)
            if amount < self.policy.settled_external_min:
                continue
            external[party] = external.get(party, 0.0) + amount
        operators = {item["agent_id"]: item["operator_org_id"] for item in self.repo.list_agents()}
        positive_pairs: set[tuple[str, str]] = set()
        cluster_count: dict[str, int] = {}
        cluster_ops: dict[str, set[str]] = {}
        evidence_sets: dict[str, set[str]] = {}
        for item in all_reports:
            if item.get("excluded"):
                continue
            reporter = str(item.get("reporter_org_id") or "")
            if item.get("kind") == "transaction_outcome" and item.get("outcome") == "settled":
                positive_pairs.add((reporter, str(item.get("agent_id") or "")))
            if report_is_negative(item):
                cluster_count[reporter] = cluster_count.get(reporter, 0) + 1
                cluster_ops.setdefault(reporter, set()).add(operators.get(item["agent_id"], ""))
                evidence_sets.setdefault(str(item.get("evidence_hash") or ""), set()).add(reporter)
        reporter_clusters = {
            reporter: {"negatives": cluster_count[reporter], "operators": len({org_id for org_id in cluster_ops[reporter] if org_id})}
            for reporter in cluster_count
        }
        evidence_reporters = {evidence: len(reporters) for evidence, reporters in evidence_sets.items()}
        edges = self._report_edges(all_reports)
        penalty = 0
        inherited: list[dict[str, Any]] = []
        if self.policy.rereg_link:
            linked_agents = []
            for link in self.repo.links_for_agent(agent["agent_id"]):
                other = self.repo.get_agent(link["linked_agent_id"])
                if other is None:
                    continue
                linked_agents.append(other)
                if not self.policy.inherit_history:
                    continue
                decay = decay_factor(str(link.get("created_at") or ""), self.stamp(), self.policy.inherit_half_life_days)
                for report in self.repo.reports_for_agent(other["agent_id"]):
                    copied = dict(report)
                    copied["decay"] = decay
                    inherited.append(copied)
            penalty = inheritance_penalty(linked_agents, now=self.stamp(), policy=self.policy)
        return ScoreContext(
            now=self.stamp(),
            reporter_created_at={org_id: item["created_at"] for org_id, item in directory.items()},
            upheld_by_reporter=upheld,
            linked_reporters=linked,
            linked_actions=actions,
            interactions=interactions,
            ring_edges=self._discounted_edges(edges) if self.policy.ring_detection else set(),
            open_dispute_ids=open_ids,
            identity_penalty=penalty,
            inherited_reports=inherited,
            external_counterparties=len(external),
            external_volume=sum(external.values()),
            positive_pairs=positive_pairs,
            reporter_clusters=reporter_clusters,
            evidence_reporters=evidence_reporters,
        )

    def _report_edges(self, all_reports: list[dict[str, Any]] | None = None) -> set[tuple[str, str]]:
        reports = self.repo.all_reports() if all_reports is None else all_reports
        operators = {item["agent_id"]: item["operator_org_id"] for item in self.repo.list_agents()}
        return {
            (item["reporter_org_id"], operators[item["agent_id"]])
            for item in reports
            if item.get("kind") == "transaction_outcome"
            and item.get("outcome") == "settled"
            and not item.get("excluded")
            and item["agent_id"] in operators
        }

    def _discounted_edges(self, edges: set[tuple[str, str]] | None = None) -> set[tuple[str, str]]:
        if not self.policy.ring_detection:
            return set()
        volumes = []
        for item in self.repo.all_interactions():
            amount = item.get("amount")
            volumes.append((item["operator_org_id"], item["counterparty_org_id"], 0.0 if amount in (None, "") else float(amount)))
        return cluster_edges(
            self._report_edges() if edges is None else edges,
            shared_groups=self.repo.org_signal_groups(),
            volumes=volumes,
            min_cluster=self.policy.ring_min_cluster,
            internal_ratio=self.policy.ring_internal_ratio,
            search_limit=self.policy.ring_search_limit,
        )

    def _report_counts(self, agent: dict[str, Any], report: dict[str, Any]) -> bool:
        if not self.policy.require_transaction_link:
            return True
        interactions = self.repo.interactions_for_agent(agent["agent_id"])
        linked = {item["counterparty_org_id"] for item in interactions}
        actions = {}
        for item in interactions:
            actions.setdefault(item["counterparty_org_id"], set()).add(item["action_id"])
        context = ScoreContext(
            now=self.stamp(),
            linked_reporters=linked,
            linked_actions=actions,
            interactions=interactions,
        )
        return report_is_linked(report, context) and link_strength(report, self.policy, context) > 0

    def _annotate(self, agent: dict[str, Any], report: dict[str, Any]) -> dict[str, Any]:
        view = dict(report)
        view["counts"] = self._report_counts(agent, report)
        return view

    def _link_denied_identity(self, record: dict[str, Any], body: dict[str, Any], at: str) -> list[str]:
        signals = _registration_signals(body)
        for kind, value in signals:
            self.repo.add_signal({"agent_id": record["agent_id"], "kind": kind, "value": value, "created_at": at})
            self.repo.add_org_signal(
                {"org_id": record["operator_org_id"], "kind": kind, "value": value, "created_at": at}
            )
        if not self.policy.rereg_link:
            return []
        denied: dict[str, dict[str, Any]] = {}

        def consider(other: dict[str, Any], *, signal: bool) -> None:
            if other["agent_id"] == record["agent_id"] or other["agent_id"] in denied:
                return
            if not agent_is_denied(other, self.policy):
                return
            reports = self.repo.reports_for_agent(other["agent_id"])
            window = lookback_days(other, self.policy, reports, signal=signal)
            if within_days(str(other.get("updated_at") or ""), at, window):
                denied[other["agent_id"]] = other

        for other in self.repo.list_agents(operator_org_id=record["operator_org_id"]):
            consider(other, signal=False)
        for kind, value in signals:
            for agent_id in self.repo.agent_ids_for_signal(kind, value):
                other = self.repo.get_agent(agent_id)
                if other is not None:
                    consider(other, signal=True)
        linked_ids = []
        for agent_id in denied:
            self.repo.add_identity_link(
                {
                    "link_id": _id("lnk"),
                    "agent_id": record["agent_id"],
                    "linked_agent_id": agent_id,
                    "signal": "denied-agent",
                    "created_at": at,
                }
            )
            linked_ids.append(agent_id)
        return linked_ids

    def _velocity_reason(self, agent: dict[str, Any], action: dict[str, Any], at: str) -> str | None:
        if not self.policy.velocity:
            return None
        day = at[:10]
        currency = str(action.get("currency") or "")
        amount = None if action.get("amount") is None else Decimal(str(action["amount"]))
        agent_count, agent_amount = window_totals(self.repo.interactions_for_agent(agent["agent_id"]), day=day, currency=currency)
        operator_count, operator_amount = window_totals(
            self.repo.interactions_for_operator(agent["operator_org_id"]),
            day=day,
            currency=currency,
        )
        probation = self._on_probation(agent, at)
        priors, quiet_days, score_rose = self._velocity_history(agent, at, currency)
        segment = str(action.get("segment") or action.get("category") or "").strip().lower() or None
        for count, total, history in (
            (agent_count, agent_amount, True),
            (operator_count, operator_amount, False),
        ):
            reason = velocity_reason(
                existing_count=count,
                existing_amount=total,
                amount=amount,
                score=int(agent.get("score") or 0),
                probation=probation,
                policy=self.policy,
                segment=segment,
                prior_daily_amounts=priors if history else None,
                quiet_days=quiet_days if history else None,
                score_rose=score_rose if history else False,
            )
            if reason:
                return reason
        return None

    def _velocity_history(self, agent: dict[str, Any], at: str, currency: str) -> tuple[list[Decimal], float | None, bool]:
        by_day: dict[str, Decimal] = {}
        latest: str | None = None
        for row in self.repo.interactions_for_agent(agent["agent_id"]):
            stamp = str(row.get("at") or "")
            if len(stamp) < 10 or stamp[:10] == at[:10]:
                continue
            if currency and row.get("currency") not in (None, "", currency):
                continue
            raw = row.get("amount")
            amount = Decimal(0) if raw in (None, "") else Decimal(str(raw))
            by_day[stamp[:10]] = by_day.get(stamp[:10], Decimal(0)) + amount
            if latest is None or stamp > latest:
                latest = stamp
        quiet = None if latest is None else age_days(latest, at)
        rose = False
        for report in self.repo.reports_for_agent(agent["agent_id"]):
            if report.get("excluded") or report.get("outcome") != "settled":
                continue
            age = age_days(str(report.get("created_at") or ""), at)
            if age is not None and 0 <= age <= self.policy.velocity_score_rise_days:
                rose = True
                break
        return list(by_day.values()), quiet, rose

    def _on_probation(self, agent: dict[str, Any], at: str) -> bool:
        for link in self.repo.links_for_agent(agent["agent_id"]):
            if within_days(str(link.get("created_at") or ""), at, self.policy.probation_days):
                return True
        return False

    def _record_interaction(
        self,
        agent: dict[str, Any],
        auth: Auth,
        body: dict[str, Any],
        action: dict[str, Any],
        agreement_id: str,
        at: str,
    ) -> None:
        counterparty = self._counterparty(auth, body)
        if counterparty is None:
            return
        action_id = str(action.get("action_id") or "")
        if not action_id:
            return
        self.repo.add_interaction(
            {
                "interaction_id": _id("ixn"),
                "agent_id": agent["agent_id"],
                "operator_org_id": agent["operator_org_id"],
                "counterparty_org_id": counterparty,
                "action_id": action_id,
                "amount": None if action.get("amount") is None else str(action["amount"]),
                "currency": action.get("currency"),
                "agreement_id": agreement_id,
                "at": at,
            }
        )

    def _counterparty(self, auth: Auth, body: dict[str, Any]) -> str | None:
        explicit = body.get("counterparty_org_id")
        org_id = str(explicit).strip() if explicit else (auth.org_id or "")
        if not org_id:
            return None
        if self.repo.get_org(org_id) is None:
            raise BureauError(400, "counterparty_org_id was not found")
        return org_id

    def _alert(self, agent: dict[str, Any], kind: str, detail: dict[str, Any]) -> None:
        at = self.stamp()
        for sub in self.repo.subscriptions_for_agent(agent["agent_id"]):
            alert = {
                "alert_id": _id("alt"),
                "agent_id": agent["agent_id"],
                "kind": kind,
                "score": agent.get("score"),
                **detail,
            }
            document = {"alert": alert, "at": at, "kata_bureau_alert": "1"}
            body = dict(document)
            if self.log_key is not None:
                body["signature"] = sign_jws(document, self.log_key, typ=ALERT_TYP)
            delivered = self._deliver(
                org_id=sub["org_id"],
                agent_id=agent["agent_id"],
                alert_id=alert["alert_id"],
                url=sub["webhook_url"],
                body=body,
            )
            self.repo.add_alert(
                {
                    "alert_id": alert["alert_id"],
                    "org_id": sub["org_id"],
                    "agent_id": agent["agent_id"],
                    "kind": kind,
                    "document": body,
                    "created_at": at,
                    "delivered": delivered,
                }
            )

    def _deliver(self, *, org_id: str, agent_id: str, alert_id: str, url: str, body: dict[str, Any]) -> bool:
        delivered = False
        for attempt in range(1, self.webhook_attempts + 1):
            if attempt > 1:
                self.webhook_sleep(self.webhook_base_delay * (2 ** (attempt - 2)))
            outcome, http_status, detail = self._post_once(url, body)
            self.repo.add_delivery(
                {
                    "delivery_id": _id("dlv"),
                    "org_id": org_id,
                    "agent_id": agent_id,
                    "alert_id": alert_id,
                    "attempt": attempt,
                    "at": self.stamp(),
                    "outcome": outcome,
                    "http_status": http_status,
                    "detail": detail,
                }
            )
            if outcome == "delivered":
                delivered = True
                break
        return delivered

    def _post_once(self, url: str, body: dict[str, Any]) -> tuple[str, int | None, str]:
        deliver = getattr(self.sender, "deliver", None)
        if callable(deliver):
            outcome, http_status, detail = deliver(url, body)
            if outcome not in {"delivered", "failed"}:
                outcome = "failed"
            if detail not in {"delivered", "timeout", "http_error", "refused"}:
                detail = "refused"
            if http_status is not None:
                try:
                    http_status = int(http_status)
                except (TypeError, ValueError):
                    http_status = None
            return outcome, http_status, detail
        try:
            self.sender.send(url, body)
        except TimeoutError:
            return "failed", None, "timeout"
        except Exception:
            return "failed", None, "refused"
        return "delivered", None, "delivered"

    def _log(self, kind: str, body: dict[str, Any]) -> None:
        if self.log_store is None or self.log_key is None:
            return
        if self.ledger_hygiene:
            from kata_service.ledger import LedgerBodyError, prepare_body

            if self.key_provider is None or self.dek_store is None:
                raise BureauError(500, "ledger hygiene needs a key provider and a data-key store")
            try:
                body = prepare_body(
                    body,
                    provider=self.key_provider,
                    dek_store=self.dek_store,
                    put_payload=self.repo.put_payload,
                    at=self.stamp(),
                )
            except LedgerBodyError as exc:
                raise BureauError(400, str(exc)) from exc
        self.log_store.append_and_sign(kind, body, self.log_key, self.now())

    def _agent(self, agent_id: str) -> dict[str, Any]:
        if any(ord(char) < 32 or ord(char) == 127 for char in agent_id):
            raise BureauError(400, "agent_id has a control character")
        agent = self.repo.get_agent(agent_id)
        if agent is None:
            raise BureauError(404, "agent was not found")
        return agent

    def _org(self, org_id: str) -> dict[str, Any]:
        org = self.repo.get_org(org_id)
        if org is None:
            raise BureauError(404, "organization was not found")
        return org

    def _consortium_member(self, auth: Auth) -> dict[str, Any]:
        self._scope(auth, "registry:read")
        if not auth.org_id:
            raise BureauError(403, "consortium membership is required")
        member = self.repo.consortium_member_for_org(auth.org_id)
        if member is None or member.get("status") != "active":
            raise BureauError(403, "consortium membership is required")
        return member

    def _caller_org(self, auth: Auth) -> dict[str, Any]:
        if not auth.org_id:
            raise BureauError(403, "an organization credential is required")
        return self._org(auth.org_id)

    def _scope(self, auth: Auth, scope: str) -> None:
        if auth.admin:
            return
        if scope not in auth.scopes:
            raise BureauError(403, "missing scope")

    def _admin(self, auth: Auth) -> None:
        if not auth.admin:
            raise BureauError(403, "admin credentials are required")

    def _screen(self, kind: str, body: dict[str, Any]) -> None:
        if not self.entity_only:
            return
        from kata_service.entity_mode import screen_request

        screen_request(kind, body)

    def _present_verify(self, agent: dict[str, Any], action: Any, payload: dict[str, Any]) -> dict[str, Any]:
        if self.entity_only:
            from kata_service.entity_mode import strip_person

            payload = strip_person(payload)
        if self.network_step_up:
            from kata_service.entity_mode import downgrade_network_deny

            payload = downgrade_network_deny(payload)
        return self._after_verify(agent, action, payload)

    def _after_verify(self, agent: dict[str, Any], action: Any, payload: dict[str, Any]) -> dict[str, Any]:
        if payload.get("verdict") == "STEP_UP":
            from kata_service.portal_devices import queue_step_up

            queue_step_up(self, agent, action if isinstance(action, dict) else None)
        return payload

    def _portal(self, auth: Auth) -> None:
        if not auth.principal_id:
            raise BureauError(401, "portal session is required")

    def _owned(self, auth: Auth, agent_id: str) -> dict[str, Any]:
        agent = self._agent(agent_id)
        if agent["principal_id"] != auth.principal_id:
            raise BureauError(404, "agent was not found")
        return agent

    def _agent_view(self, auth: Auth, agent: dict[str, Any]) -> dict[str, Any]:
        view = {
            "agent_id": agent["agent_id"],
            "status": agent["status"],
            "verification_level": agent["verification_level"],
            "assurance_level": agent.get("assurance_level") or self._assurance(agent),
            "algorithm": agent["algorithm"],
            "fingerprint": agent["fingerprint"],
            "public_key": agent["public_key"],
            "operator_org_id": agent["operator_org_id"],
            "score": agent.get("score", 0),
            "risk": self.policy.weights.risk(int(agent.get("score") or 0)),
            "model_version": self.policy.weights.model_version,
            "score_reasons": agent.get("score_reasons", []),
            "cold_start": agent.get("cold_start", True),
            "environment": "test" if agent.get("is_test") else "live",
            "created_at": agent["created_at"],
            "updated_at": agent["updated_at"],
        }
        if agent.get("entity_kind"):
            view["entity_kind"] = agent["entity_kind"]
        if auth.admin or auth.org_id == agent["operator_org_id"] or auth.principal_id == agent["principal_id"]:
            view["principal_id"] = agent["principal_id"]
            view["proofings"] = [_public_proof(item) for item in self.repo.proofings_for_agent(agent["agent_id"])]
        return view

    def _assurance(self, agent: dict[str, Any]) -> str:
        methods = {item["method"] for item in self.repo.proofings_for_agent(agent["agent_id"])}
        return effective_assurance(
            agent["verification_level"],
            methods,
            require_proofing=self.policy.require_proofing,
            operator_established=self._operator_established(agent),
        )

    def _operator_established(self, agent: dict[str, Any]) -> bool:
        if not self.policy.operator_history:
            return False
        org = self.repo.get_org(agent["operator_org_id"])
        if org is None or org.get("status") != "active":
            return False
        age = age_days(str(org.get("created_at") or ""), self.stamp())
        if age is None or age < self.policy.operator_history_days:
            return False
        reporters = {item["report_id"]: item["reporter_org_id"] for item in self.repo.all_reports()}
        for item in self.repo.list_disputes():
            if item.get("status") == "resolved" and item.get("outcome") == "upheld":
                if reporters.get(item["report_id"]) == org["org_id"]:
                    return False
        return True

    def _record_proof(self, agent_id: str, org_id: str, method: str, evidence: str, at: str) -> dict[str, Any]:
        if method not in PROOFING_METHODS:
            raise BureauError(400, "method is not a proofing method")
        for item in self.repo.proofings_for_agent(agent_id):
            if item["method"] == method and item["evidence_hash"] == evidence:
                return item
        record = {
            "proofing_id": _id("prf"),
            "agent_id": agent_id,
            "org_id": org_id,
            "method": method,
            "evidence_hash": evidence,
            "created_at": at,
        }
        self.repo.add_proofing(record)
        return record


def org_name(repo: MemoryRepo, org_id: str) -> str:
    org = repo.get_org(org_id)
    return "" if org is None else org["name"]


def _principal_jwk(agreement: Agreement) -> dict[str, Any]:
    for mandate in agreement.mandates:
        jwk = (mandate.get("principal") or {}).get("public_key")
        if isinstance(jwk, dict):
            try:
                public_key_from_jwk(jwk)
            except KataError:
                break
            return jwk
    raise BureauError(400, "agreement has no principal public key")


def _agreement_summary(record: dict[str, Any]) -> dict[str, Any]:
    document = record["document"]
    intents = []
    for mandate in document.get("mandates") or []:
        intent = mandate.get("intent") or {}
        limits = mandate.get("limits") or {}
        intents.append(
            {
                "intent_id": intent.get("intent_id"),
                "purpose": intent.get("purpose"),
                "maximum_amount": intent.get("maximum_amount"),
                "currency": intent.get("currency"),
                "cumulative_maximum": limits.get("cumulative_maximum"),
                "expires_at": mandate.get("expires_at"),
            }
        )
    parent = (document.get("mandates") or [{}])[0].get("parent_limits") or {}
    return {
        "agreement_id": record["agreement_id"],
        "agent_id": record["agent_id"],
        "status": record["status"],
        "updated_at": record["updated_at"],
        "parent_cumulative_maximum": parent.get("cumulative_maximum"),
        "intents": intents,
    }


def _registration_signals(body: dict[str, Any]) -> list[tuple[str, str]]:
    signals: list[tuple[str, str]] = []
    for kind, field in (
        ("device", "device_signal"),
        ("key", "key_signal"),
        ("payment", "payment_instrument"),
        ("timing", "timing_signal"),
    ):
        raw = body.get(field)
        if raw:
            signals.append((kind, _short(str(raw), field, 128)))
    evidence = str(body.get("proofing_evidence") or "").strip()
    if _EVIDENCE.match(evidence):
        signals.append(("evidence", evidence))
    return signals


def _fingerprint(value: str) -> str:
    if not _EVIDENCE.match(value):
        raise BureauError(400, "fingerprint must be sha256 and 64 hex characters")
    return value


def _public_member(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "member_id": record["member_id"],
        "org_id": record["org_id"],
        "status": record["status"],
        "created_at": record["created_at"],
    }


def _public_proof(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "proofing_id": record["proofing_id"],
        "method": record["method"],
        "evidence_hash": record["evidence_hash"],
        "created_at": record["created_at"],
    }


def _public_report(record: dict[str, Any], *, full: bool) -> dict[str, Any]:
    view = {
        "report_id": record["report_id"],
        "agent_id": record["agent_id"],
        "kind": record["kind"],
        "evidence_hash": record["evidence_hash"],
        "created_at": record["created_at"],
        "excluded": bool(record.get("excluded")),
        "counts": bool(record.get("counts")),
    }
    if record.get("action_id"):
        view["action_id"] = record["action_id"]
    if full:
        view["summary"] = record["summary"]
        view["outcome"] = record.get("outcome")
        view["reporter_org_id"] = record["reporter_org_id"]
    return view


def _public_delivery(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "delivery_id": record["delivery_id"],
        "alert_id": record["alert_id"],
        "agent_id": record["agent_id"],
        "attempt": record["attempt"],
        "at": record["at"],
        "outcome": record["outcome"],
        "http_status": record.get("http_status"),
        "detail": record["detail"],
    }


def _public_key(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "key_id": record["key_id"],
        "org_id": record["org_id"],
        "name": record["name"],
        "prefix": record["prefix"],
        "environment": "test" if _key_is_test("", record) else "live",
        "scopes": list(record["scopes"]),
        "created_at": record["created_at"],
        "revoked_at": record.get("revoked_at"),
    }


def _key_is_test(token: str, record: dict[str, Any] | None = None) -> bool:
    if token.startswith("gab_test_"):
        return True
    if record is None:
        return False
    if record.get("environment") == "test":
        return True
    return str(record.get("prefix") or "").startswith("gab_test_")


def _new_key(test: bool = False) -> tuple[str, str, str]:
    """Live tokens use gab_. Test tokens use gab_test_. The stored prefix omits the secret."""

    visible = secrets.token_hex(4)
    if test:
        prefix = f"gab_test_{visible}"
        token = f"{prefix}_{secrets.token_urlsafe(24)}"
    else:
        prefix = visible
        token = f"gab_{prefix}_{secrets.token_urlsafe(24)}"
    return token, prefix, token_hash(token)


def _id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(8)}"


def _short(value: str, label: str, limit: int) -> str:
    text = value.strip()
    if not text or len(text) > limit:
        raise BureauError(400, f"{label} must be a short phrase")
    return text


def _email(value: str) -> str:
    text = normalize_email(value)
    if not _EMAIL.match(text):
        raise BureauError(400, "email is invalid")
    return text


def _checkout_revocations(service: BureauService, agent: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if agent.get("status") == "revoked":
        rows.append({"kind": "agent", "id": agent.get("agent_id"), "at": agent.get("updated_at")})
    for agreement in service.repo.list_agreements(str(agent.get("agent_id") or "")):
        if agreement.get("status") == "revoked":
            rows.append({"kind": "agreement", "id": agreement.get("agreement_id"), "at": agreement.get("updated_at")})
    return rows


def _webhook(value: str) -> str:
    parsed = urlparse(value.strip())
    host = (parsed.hostname or "").lower()
    if parsed.scheme == "https" and host and host not in {"localhost", "127.0.0.1", "::1"}:
        return value.strip()
    raise BureauError(400, "webhook_url must be https")


