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
import json
import re
import secrets
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol
from urllib.parse import urlparse

from kata_intent.agreement import Agreement
from kata_intent.canonical import canonical_bytes
from kata_intent.errors import KataError
from kata_intent.jws import sign_jws
from kata_intent.keys import PrivateKey, public_key_from_jwk
from kata_intent.values import hash_document

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
_AGENT_ID = re.compile(r"^[A-Za-z0-9._-]{1,80}$")
_EVIDENCE = re.compile(r"^sha256:[0-9a-f]{64}$")
_EMAIL = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,120}$")
ALERT_TYP = "kata-bureau-alert+jws"

_VERIFY_POINTS = {
    "unverified": 0,
    "key_bound": 40,
    "operator_verified": 120,
    "institution_attested": 200,
}
_REPORTER_WEIGHT = {
    "bank_issuer": 1.0,
    "processor_psp": 1.0,
    "wallet": 0.8,
    "merchant": 0.7,
    "agent_operator": 0.4,
}


class BureauError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


@dataclass
class Auth:
    admin: bool = False
    org_id: str | None = None
    key_id: str | None = None
    principal_id: str | None = None
    scopes: frozenset[str] = field(default_factory=frozenset)
    kind: str = "anonymous"


class Mailer(Protocol):
    def send_magic_link(self, email: str, url: str) -> None: ...


class WebhookSender(Protocol):
    def send(self, url: str, body: dict[str, Any]) -> None: ...


class ConsoleMailer:
    """Development sender. The link is printed, not delivered to a network."""

    def send_magic_link(self, email: str, url: str) -> None:
        print(f"GAB magic link for {email}: {url}", flush=True)


class HttpWebhookSender:
    def send(self, url: str, body: dict[str, Any]) -> None:
        import urllib.request

        data = json.dumps(body).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json", "User-Agent": "gab-service/0.1"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=3) as response:
            response.read()


class RecordingSender:
    def __init__(self) -> None:
        self.sent: list[tuple[str, dict[str, Any]]] = []

    def send(self, url: str, body: dict[str, Any]) -> None:
        self.sent.append((url, body))


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def email_hash(email: str) -> str:
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
) -> dict[str, Any]:
    """Explainable 0–1000 score for an agent. Individuals are not scored."""

    parts: list[tuple[str, int, str]] = []
    identity = _VERIFY_POINTS.get(verification_level, 0)
    parts.append(("IDENTITY_ASSURANCE", identity, verification_level))
    if operator_status == "active":
        parts.append(("OPERATOR_VERIFICATION", 80, "operator active"))
    else:
        parts.append(("OPERATOR_INACTIVE", -40, operator_status))

    resolved = {
        item["report_id"]: item
        for item in disputes
        if item.get("status") == "resolved" and item.get("outcome")
    }
    best: dict[tuple[str, str], tuple[float, dict[str, Any]]] = {}
    for report in reports:
        if report.get("excluded"):
            continue
        weight = _REPORTER_WEIGHT.get(reporter_types.get(report["reporter_org_id"], ""), 0.5)
        if report["reporter_org_id"] == operator_org_id:
            weight *= 0.25
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

    for (_key, (weight, report)) in best.items():
        points, code = _report_points(report, weight)
        if points:
            parts.append((code, points, report["kind"]))

    raw = 500 + sum(points for _code, points, _detail in parts)
    score = max(0, min(1000, int(raw)))
    ranked = sorted(parts, key=lambda item: abs(item[1]), reverse=True)
    reasons = [
        {"code": code, "points": points, "detail": detail}
        for code, points, detail in ranked
        if points != 0
    ][:4]
    cold = not best
    if cold:
        reasons = [{"code": "COLD_START", "points": 0, "detail": "no contributing reports"}, *reasons][:4]
    return {"score": score, "reasons": reasons, "cold_start": cold}


def _report_points(report: dict[str, Any], weight: float) -> tuple[int, str]:
    kind = report["kind"]
    outcome = report.get("outcome") or ""
    if kind == "fraud_incident":
        return (int(round(-120 * weight)), "FRAUD_INCIDENT")
    if kind == "chargeback":
        return (int(round(-80 * weight)), "CHARGEBACK")
    if kind == "policy_violation":
        return (int(round(-40 * weight)), "POLICY_VIOLATION")
    if kind == "transaction_outcome" and outcome == "settled":
        return (int(round(8 * weight)), "SETTLED_ACTIVITY")
    if kind == "transaction_outcome" and outcome == "loss":
        return (int(round(-30 * weight)), "LOSS_ACTIVITY")
    return (0, "REPORT")


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
        self.magic: dict[str, dict[str, Any]] = {}
        self.sessions: dict[str, dict[str, Any]] = {}
        self.org_logins: dict[str, dict[str, Any]] = {}
        self.agents: dict[str, dict[str, Any]] = {}
        self.by_fingerprint: dict[str, str] = {}
        self.agreements: dict[str, dict[str, Any]] = {}
        self.reports: list[dict[str, Any]] = []
        self.inquiries: list[dict[str, Any]] = []
        self.subscriptions: list[dict[str, Any]] = []
        self.alerts: list[dict[str, Any]] = []
        self.disputes: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    def migration_versions(self) -> list[str]:
        return ["001_bureau.sql"]

    def create_org(self, record: dict[str, Any]) -> None:
        with self._lock:
            self.orgs[record["org_id"]] = dict(record)

    def get_org(self, org_id: str) -> dict[str, Any] | None:
        with self._lock:
            item = self.orgs.get(org_id)
            return dict(item) if item else None

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

    def list_audit(self, org_id: str | None) -> list[dict[str, Any]]:
        with self._lock:
            rows = self.audit if org_id is None else [item for item in self.audit if item.get("org_id") == org_id]
            return [dict(item) for item in rows]

    def hit_rate(self, subject: str, window: str) -> int:
        with self._lock:
            key = (subject, window)
            self.rate[key] = self.rate.get(key, 0) + 1
            return self.rate[key]

    def ensure_principal(self, principal_id: str, at: str) -> None:
        with self._lock:
            self.principals.setdefault(principal_id, {"principal_id": principal_id, "created_at": at})

    def upsert_login(self, email: str, principal_id: str, at: str) -> None:
        with self._lock:
            self.logins[email_hash(email)] = {
                "email": normalize_email(email),
                "principal_id": principal_id,
                "created_at": at,
            }

    def login_by_email(self, email: str) -> dict[str, Any] | None:
        return self.login_by_hash(email_hash(email))

    def login_by_hash(self, digest: str) -> dict[str, Any] | None:
        with self._lock:
            item = self.logins.get(digest)
            return dict(item) if item else None

    def upsert_org_login(self, email: str, org_id: str, at: str) -> None:
        with self._lock:
            self.org_logins[email_hash(email)] = {
                "email": normalize_email(email),
                "org_id": org_id,
                "created_at": at,
            }

    def org_login_by_email(self, email: str) -> dict[str, Any] | None:
        return self.org_login_by_hash(email_hash(email))

    def org_login_by_hash(self, digest: str) -> dict[str, Any] | None:
        with self._lock:
            item = self.org_logins.get(digest)
            return dict(item) if item else None

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

    def save_agent(self, record: dict[str, Any]) -> None:
        with self._lock:
            self.agents[record["agent_id"]] = dict(record)
            self.by_fingerprint[record["fingerprint"]] = record["agent_id"]

    def get_agent(self, agent_id: str) -> dict[str, Any] | None:
        with self._lock:
            item = self.agents.get(agent_id)
            return dict(item) if item else None

    def agent_by_fingerprint(self, fingerprint: str) -> dict[str, Any] | None:
        with self._lock:
            agent_id = self.by_fingerprint.get(fingerprint)
            if agent_id is None:
                return None
            return dict(self.agents[agent_id])

    def list_agents(self, *, operator_org_id: str | None = None, principal_id: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            rows = list(self.agents.values())
            if operator_org_id is not None:
                rows = [item for item in rows if item["operator_org_id"] == operator_org_id]
            if principal_id is not None:
                rows = [item for item in rows if item["principal_id"] == principal_id]
            return [dict(item) for item in rows]

    def save_agreement(self, record: dict[str, Any]) -> None:
        with self._lock:
            self.agreements[record["agreement_id"]] = dict(record)

    def get_agreement(self, agreement_id: str) -> dict[str, Any] | None:
        with self._lock:
            item = self.agreements.get(agreement_id)
            return dict(item) if item else None

    def list_agreements(self, agent_id: str) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(item) for item in self.agreements.values() if item["agent_id"] == agent_id]

    def add_report(self, record: dict[str, Any]) -> None:
        with self._lock:
            for item in self.reports:
                if (
                    item["reporter_org_id"] == record["reporter_org_id"]
                    and item["agent_id"] == record["agent_id"]
                    and item["kind"] == record["kind"]
                    and item["evidence_hash"] == record["evidence_hash"]
                ):
                    raise BureauError(409, "duplicate report")
            self.reports.append(dict(record))

    def reports_for_agent(self, agent_id: str) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(item) for item in self.reports if item["agent_id"] == agent_id]

    def reports_by_org_on_day(self, org_id: str, day: str) -> int:
        with self._lock:
            return sum(1 for item in self.reports if item["reporter_org_id"] == org_id and item["created_at"].startswith(day))

    def org_has_report(self, org_id: str) -> bool:
        with self._lock:
            return any(item["reporter_org_id"] == org_id for item in self.reports)

    def get_report(self, report_id: str) -> dict[str, Any] | None:
        with self._lock:
            for item in self.reports:
                if item["report_id"] == report_id:
                    return dict(item)
            return None

    def set_report_excluded(self, report_id: str, excluded: bool) -> None:
        with self._lock:
            for item in self.reports:
                if item["report_id"] == report_id:
                    item["excluded"] = excluded

    def add_inquiry(self, record: dict[str, Any]) -> None:
        with self._lock:
            self.inquiries.append(dict(record))

    def inquiries_for_principal(self, principal_id: str) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(item) for item in self.inquiries if item["principal_id"] == principal_id]

    def add_subscription(self, record: dict[str, Any]) -> None:
        with self._lock:
            for item in self.subscriptions:
                if item["org_id"] == record["org_id"] and item["agent_id"] == record["agent_id"] and item["webhook_url"] == record["webhook_url"]:
                    raise BureauError(409, "subscription already exists")
            self.subscriptions.append(dict(record))

    def subscriptions_for_agent(self, agent_id: str) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(item) for item in self.subscriptions if item["agent_id"] == agent_id]

    def subscriptions_for_org(self, org_id: str) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(item) for item in self.subscriptions if item["org_id"] == org_id]

    def delete_subscription(self, subscription_id: str, org_id: str) -> bool:
        with self._lock:
            before = len(self.subscriptions)
            self.subscriptions = [
                item for item in self.subscriptions if not (item["subscription_id"] == subscription_id and item["org_id"] == org_id)
            ]
            return len(self.subscriptions) != before

    def add_alert(self, record: dict[str, Any]) -> None:
        with self._lock:
            self.alerts.append(dict(record))

    def alerts_for_org(self, org_id: str) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(item) for item in self.alerts if item["org_id"] == org_id]

    def add_dispute(self, record: dict[str, Any]) -> None:
        with self._lock:
            self.disputes.append(dict(record))

    def list_disputes(self) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(item) for item in self.disputes]

    def disputes_for_principal(self, principal_id: str) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(item) for item in self.disputes if item["principal_id"] == principal_id]

    def get_dispute(self, dispute_id: str) -> dict[str, Any] | None:
        with self._lock:
            for item in self.disputes:
                if item["dispute_id"] == dispute_id:
                    return dict(item)
            return None

    def save_dispute(self, record: dict[str, Any]) -> None:
        with self._lock:
            for index, item in enumerate(self.disputes):
                if item["dispute_id"] == record["dispute_id"]:
                    self.disputes[index] = dict(record)
                    return

    def reporter_types(self) -> dict[str, str]:
        with self._lock:
            return {org_id: item["org_type"] for org_id, item in self.orgs.items()}


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
    ) -> None:
        self.repo = repo
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
        if admin_token and hmac.compare_digest(token, admin_token):
            return Auth(admin=True, scopes=frozenset(SCOPES), kind="admin", key_id="admin")
        key = self.repo.key_by_hash(token_hash(token))
        if key is not None:
            if key.get("revoked_at"):
                raise BureauError(401, "api key is revoked")
            return Auth(
                org_id=key["org_id"],
                key_id=key["key_id"],
                scopes=frozenset(key["scopes"]),
                kind="key",
            )
        session = self.repo.get_session(token_hash(token))
        if session is not None:
            if session["expires_at"] < self.stamp():
                raise BureauError(401, "session expired")
            if session["kind"] == "portal":
                return Auth(principal_id=session["subject_id"], kind="portal")
            org = self.repo.get_org(session["subject_id"])
            if org is None:
                raise BureauError(401, "session is not valid")
            return Auth(
                org_id=org["org_id"],
                scopes=frozenset(default_scopes(org["org_type"])),
                kind="org_session",
            )
        raise BureauError(401, "credentials are required")

    def hit_rate(self, subject: str) -> int:
        window = self.now().strftime("%Y-%m-%dT%H:%M")
        return self.repo.hit_rate(subject, window)

    def create_org(self, auth: Auth, name: str, org_type: str) -> dict[str, Any]:
        self._admin(auth)
        if org_type not in ORG_TYPES:
            raise BureauError(400, "org_type is not a bureau participant type")
        name = _short(name, "name", 120)
        record = {
            "org_id": _id("org"),
            "name": name,
            "org_type": org_type,
            "status": "active",
            "created_at": self.stamp(),
        }
        self.repo.create_org(record)
        return record

    def create_key(self, auth: Auth, org_id: str, name: str, scopes: list[str] | None) -> dict[str, Any]:
        org = self._org(org_id)
        if not auth.admin and auth.org_id != org_id:
            raise BureauError(404, "organization was not found")
        self._scope(auth, "keys:manage")
        chosen = list(scopes or default_scopes(org["org_type"]))
        if any(item not in SCOPES for item in chosen):
            raise BureauError(400, "unknown scope")
        token, prefix, digest = _new_key()
        record = {
            "key_id": _id("key"),
            "org_id": org_id,
            "name": _short(name, "name", 80),
            "prefix": prefix,
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
        created = self.create_key(auth, current["org_id"], current["name"], list(current["scopes"]))
        return created

    def register_org_email(self, auth: Auth, org_id: str, email: str) -> dict[str, str]:
        if not auth.admin and auth.org_id != org_id:
            raise BureauError(404, "organization was not found")
        self._scope(auth, "keys:manage")
        self._org(org_id)
        address = _email(email)
        self.repo.upsert_org_login(address, org_id, self.stamp())
        return {"registered": "true", "org_id": org_id}

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
        return self._agent_view(auth, record)

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

    def set_status(self, auth: Auth, agent_id: str, status: str) -> dict[str, Any]:
        if status not in AGENT_STATUSES:
            raise BureauError(400, "status is not active, suspended, or revoked")
        agent = self._agent(agent_id)
        if not auth.admin and auth.org_id != agent["operator_org_id"] and auth.principal_id != agent["principal_id"]:
            raise BureauError(404, "agent was not found")
        if auth.principal_id and status != "revoked":
            raise BureauError(403, "a principal can revoke the agent")
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
        return self._agent_view(auth, agent)

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
        agent_id = str(body.get("agent_id") or "")
        agent = self._agent(agent_id)
        action = body.get("action")
        if not isinstance(action, dict):
            raise BureauError(400, "action must be an object")
        if agent["status"] != "active":
            return {"verdict": "DENY", "kata_decision": "BLOCK", "reasons": ["AGENT_NOT_ACTIVE"], "messages": ["Agent is not active."], "agent_id": agent_id}
        active = [item for item in self.repo.list_agreements(agent_id) if item["status"] == "active"]
        chosen_id = body.get("agreement_id")
        if chosen_id:
            active = [item for item in active if item["agreement_id"] == chosen_id]
        if not active:
            return {"verdict": "DENY", "kata_decision": "BLOCK", "reasons": ["NO_ACTIVE_AGREEMENT"], "messages": ["No active agreement is stored."], "agent_id": agent_id}
        if len(active) > 1 and not chosen_id:
            return {"verdict": "STEP_UP", "kata_decision": "STEP_UP", "reasons": ["AGREEMENT_NOT_SELECTED"], "messages": ["More than one active agreement is stored."], "agent_id": agent_id}
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
            try:
                agreement.record_allowed(action, at=at, intent_id=body.get("intent_id"))
            except KataError as exc:
                raise BureauError(400, str(exc)) from exc
            record["document"] = agreement.to_dict()
            record["updated_at"] = at
            self.repo.save_agreement(record)
        payload = result.to_dict()
        payload["agent_id"] = agent_id
        payload["agreement_id"] = record["agreement_id"]
        return payload

    def report(self, auth: Auth, body: dict[str, Any]) -> dict[str, Any]:
        self._scope(auth, "report")
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
        record = {
            "report_id": _id("rpt"),
            "agent_id": agent["agent_id"],
            "reporter_org_id": org["org_id"],
            "kind": kind,
            "evidence_hash": evidence,
            "summary": summary,
            "outcome": outcome,
            "created_at": self.stamp(),
            "excluded": False,
        }
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
            body["reports"] = [_public_report(item, full=True) for item in reports]
        return body

    def inquire(self, auth: Auth, body: dict[str, Any]) -> dict[str, Any]:
        self._scope(auth, "inquire")
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

    def list_audit(self, auth: Auth) -> list[dict[str, Any]]:
        self._scope(auth, "keys:manage")
        org_id = None if auth.admin else auth.org_id
        return self.repo.list_audit(org_id)

    def request_portal_link(self, email: str) -> dict[str, bool]:
        address = _email(email)
        at = self.stamp()
        existing = self.repo.login_by_email(address)
        if existing is None:
            principal_id = _id("prn")
            self.repo.ensure_principal(principal_id, at)
            self.repo.upsert_login(address, principal_id, at)
        self._send_link("portal", address, email_hash(address))
        return {"sent": True}

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
            login = self.repo.login_by_hash(record["subject_hash"])
            if login is None:
                raise BureauError(401, "magic link is not valid")
            session = self._session("portal", login["principal_id"])
            return {"token": session, "kind": "portal", "principal_id": login["principal_id"]}
        login = self.repo.org_login_by_hash(record["subject_hash"])
        if login is None:
            raise BureauError(401, "magic link is not valid")
        session = self._session("org", login["org_id"])
        return {"token": session, "kind": "org", "org_id": login["org_id"]}

    def portal_agents(self, auth: Auth) -> list[dict[str, Any]]:
        self._portal(auth)
        return [self._agent_view(auth, item) for item in self.repo.list_agents(principal_id=auth.principal_id)]

    def portal_authorizations(self, auth: Auth, agent_id: str) -> list[dict[str, Any]]:
        self._portal(auth)
        agent = self._owned(auth, agent_id)
        return [_agreement_summary(item) for item in self.repo.list_agreements(agent["agent_id"])]

    def portal_reports(self, auth: Auth, agent_id: str) -> list[dict[str, Any]]:
        self._portal(auth)
        agent = self._owned(auth, agent_id)
        return [_public_report(item, full=True) for item in self.repo.reports_for_agent(agent["agent_id"])]

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

    def portal_revoke_agreement(self, auth: Auth, agreement_id: str) -> dict[str, Any]:
        self._portal(auth)
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

    def file_dispute(self, auth: Auth, report_id: str, statement: str) -> dict[str, Any]:
        self._portal(auth)
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
        self.repo.put_magic(
            {"token_hash": token_hash(token), "kind": kind, "subject_hash": subject_hash, "expires_at": expires, "used_at": None}
        )
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

    def _rescore(self, agent: dict[str, Any]) -> None:
        operator = self.repo.get_org(agent["operator_org_id"])
        reports = self.repo.reports_for_agent(agent["agent_id"])
        disputes = [item for item in self.repo.list_disputes() if any(item["report_id"] == report["report_id"] for report in reports)]
        scored = trust_score(
            verification_level=agent["verification_level"],
            operator_status="active" if operator and operator["status"] == "active" else "inactive",
            operator_org_id=agent["operator_org_id"],
            reports=reports,
            disputes=disputes,
            reporter_types=self.repo.reporter_types(),
        )
        agent["score"] = scored["score"]
        agent["score_reasons"] = scored["reasons"]
        agent["cold_start"] = scored["cold_start"]

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
            delivered = False
            if self.log_key is not None:
                body["signature"] = sign_jws(document, self.log_key, typ=ALERT_TYP)
            try:
                self.sender.send(sub["webhook_url"], body)
                delivered = True
            except Exception:
                delivered = False
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

    def _log(self, kind: str, body: dict[str, Any]) -> None:
        if self.log_store is None or self.log_key is None:
            return
        self.log_store.append_and_sign(kind, body, self.log_key, self.now())

    def _agent(self, agent_id: str) -> dict[str, Any]:
        agent = self.repo.get_agent(agent_id)
        if agent is None:
            raise BureauError(404, "agent was not found")
        return agent

    def _org(self, org_id: str) -> dict[str, Any]:
        org = self.repo.get_org(org_id)
        if org is None:
            raise BureauError(404, "organization was not found")
        return org

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
            "algorithm": agent["algorithm"],
            "fingerprint": agent["fingerprint"],
            "public_key": agent["public_key"],
            "operator_org_id": agent["operator_org_id"],
            "score": agent.get("score", 0),
            "score_reasons": agent.get("score_reasons", []),
            "cold_start": agent.get("cold_start", True),
            "created_at": agent["created_at"],
            "updated_at": agent["updated_at"],
        }
        if auth.admin or auth.org_id == agent["operator_org_id"] or auth.principal_id == agent["principal_id"]:
            view["principal_id"] = agent["principal_id"]
        return view


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


def _public_report(record: dict[str, Any], *, full: bool) -> dict[str, Any]:
    view = {
        "report_id": record["report_id"],
        "agent_id": record["agent_id"],
        "kind": record["kind"],
        "evidence_hash": record["evidence_hash"],
        "created_at": record["created_at"],
        "excluded": bool(record.get("excluded")),
    }
    if full:
        view["summary"] = record["summary"]
        view["outcome"] = record.get("outcome")
        view["reporter_org_id"] = record["reporter_org_id"]
    return view


def _public_key(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "key_id": record["key_id"],
        "org_id": record["org_id"],
        "name": record["name"],
        "prefix": record["prefix"],
        "scopes": list(record["scopes"]),
        "created_at": record["created_at"],
        "revoked_at": record.get("revoked_at"),
    }


def _new_key() -> tuple[str, str, str]:
    prefix = secrets.token_hex(4)
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


def _webhook(value: str) -> str:
    parsed = urlparse(value.strip())
    host = (parsed.hostname or "").lower()
    if parsed.scheme == "https":
        return value.strip()
    if parsed.scheme == "http" and host in {"localhost", "127.0.0.1"}:
        return value.strip()
    raise BureauError(400, "webhook_url must be https")


