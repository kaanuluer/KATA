# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Demo data for the Global Agent Bureau.

The demo API keys and signing seeds are public. They are inserted only when
this script is run with ``--demo`` or when the process is started with
``GAB_DEMO=1``. Do not use them as production credentials.
"""

from __future__ import annotations

import hashlib
from dataclasses import replace

from kata_intent import Actor, Agreement, private_key_from_seed

from kata_service.bureau import Auth, BureauService, token_hash
from kata_service.settings import Settings

DEMO_ADMIN_TOKEN = "gab-demo-admin"
DEMO_WALLET_KEY = "gab_demo_wallet_public"
DEMO_OPERATOR_KEY = "gab_demo_operator_public"
DEMO_MERCHANT_KEY = "gab_demo_merchant_public"
DEMO_PORTAL_EMAIL = "principal@example.com"
DEMO_ORG_EMAIL = "ops@harbor.example"


def demo_settings(settings: Settings) -> Settings:
    """Fill public demo credentials when the process is explicitly in demo mode."""

    updates: dict = {"dev_mailbox": True, "demo": True}
    if settings.log_signing_seed is None:
        updates["log_signing_seed"] = hashlib.sha256(b"gab-demo-log").digest()
    if not settings.admin_token:
        updates["admin_token"] = DEMO_ADMIN_TOKEN
    return replace(settings, **updates)


def seed_demo(service: BureauService) -> dict[str, str]:
    """Insert a wallet, an operator, a merchant, one agent, and one signed intent.

    A second call finds the same public demo keys and does not insert another copy.
    """

    admin = Auth(admin=True, kind="admin", scopes=frozenset())
    already = service.repo.get_agent("shopper-01") is not None
    operator = _ensure_participant(
        service,
        admin,
        "Harbor Agents",
        "agent_operator",
        "Harbor demo",
        DEMO_OPERATOR_KEY,
        ["registry:read", "registry:write", "verify", "report", "alerts", "keys:manage"],
    )
    wallet = _ensure_participant(
        service,
        admin,
        "Northwind Wallet",
        "wallet",
        "Northwind demo",
        DEMO_WALLET_KEY,
        ["registry:read", "registry:write", "inquire", "verify", "report", "alerts", "keys:manage"],
    )
    merchant = _ensure_participant(
        service,
        admin,
        "Techstore",
        "merchant",
        "Techstore demo",
        DEMO_MERCHANT_KEY,
        ["registry:read", "inquire", "verify", "report", "alerts", "keys:manage"],
    )
    service.repo.upsert_org_login(DEMO_ORG_EMAIL, operator["org_id"], service.stamp())

    operator_auth = service.authenticate(DEMO_OPERATOR_KEY, admin_token=None)
    principal_key = private_key_from_seed(hashlib.sha256(b"gab-demo-principal").digest())
    agent_key = private_key_from_seed(hashlib.sha256(b"gab-demo-agent").digest())
    agent = service.repo.get_agent("shopper-01")
    if agent is None:
        agent = service.register_agent(
            operator_auth,
            {
                "agent_id": "shopper-01",
                "principal_id": "prn_demo",
                "public_key": agent_key.public.to_jwk(),
                "verification_level": "operator_verified",
            },
        )
    service.repo.upsert_login(DEMO_PORTAL_EMAIL, "prn_demo", service.stamp())
    at = "2026-10-04T13:55:00Z"
    agreement = Agreement.propose(
        agreement_id="agr_demo",
        principal={"display_name": "Demo Principal", "id": "prn_demo", "type": "human"},
        agent={"agent_id": "shopper-01"},
        agent_public_key=agent_key.public,
        intent={
            "allowed_actions": ["purchase"],
            "currency": "CAD",
            "intent_id": "int_laptop",
            "maximum_amount": 1500,
            "purpose": "purchase",
            "time_limit": "2026-12-31T23:59:59Z",
            "version": 1,
        },
        limits={"cumulative_maximum": 2000},
        parent_limits={"cumulative_maximum": 2000, "currency": "CAD", "maximum_amount": 1500},
        actor=Actor("agent", "shopper-01"),
        at=at,
        expires_at="2026-12-31T23:59:59Z",
        delegation_id="dlg_demo",
    )
    agreement.accept(principal_key, at, confirmed_text=agreement.rendering_preview())
    if service.repo.get_agreement("agr_demo") is None:
        service.store_intent(operator_auth, "shopper-01", agreement.to_dict())
    current = service.repo.get_agent("shopper-01") or agent
    wallet_auth = service.authenticate(DEMO_WALLET_KEY, admin_token=None)
    if current.get("verification_level") != "institution_attested":
        service.attest_agent(wallet_auth, "shopper-01")
    merchant_auth = service.authenticate(DEMO_MERCHANT_KEY, admin_token=None)
    hook = "http://127.0.0.1:8765/demo-hook"
    subscribed = any(
        item["agent_id"] == "shopper-01" and item["webhook_url"] == hook
        for item in service.repo.subscriptions_for_org(merchant["org_id"])
    )
    if not subscribed:
        service.subscribe(merchant_auth, "shopper-01", hook)
    evidence = "sha256:" + "ab" * 32
    reported = any(
        item["kind"] == "chargeback" and item["evidence_hash"] == evidence and item["reporter_org_id"] == merchant["org_id"]
        for item in service.repo.reports_for_agent("shopper-01")
    )
    service.repo.set_org_created_at(merchant["org_id"], "2026-01-01T00:00:00Z")
    linked = any(
        item["counterparty_org_id"] == merchant["org_id"] for item in service.repo.interactions_for_agent("shopper-01")
    )
    if not linked:
        service.repo.add_interaction(
            {
                "interaction_id": "ixn_demo_laptop",
                "agent_id": "shopper-01",
                "operator_org_id": operator["org_id"],
                "counterparty_org_id": merchant["org_id"],
                "action_id": "act_demo_laptop",
                "amount": "1300",
                "currency": "CAD",
                "agreement_id": "agr_demo",
                "at": at,
            }
        )
    if not reported:
        service.report(
            merchant_auth,
            {
                "agent_id": "shopper-01",
                "kind": "chargeback",
                "evidence_hash": evidence,
                "summary": "Cardholder disputed the laptop purchase.",
                "action_id": "act_demo_laptop",
            },
        )
    else:
        scored = service.repo.get_agent("shopper-01")
        if scored is not None:
            service._rescore(scored)
            service.repo.save_agent(scored)
    return {
        "admin_token": DEMO_ADMIN_TOKEN,
        "operator_key": DEMO_OPERATOR_KEY,
        "wallet_key": DEMO_WALLET_KEY,
        "merchant_key": DEMO_MERCHANT_KEY,
        "agent_id": agent["agent_id"],
        "agreement_id": "agr_demo",
        "portal_email": DEMO_PORTAL_EMAIL,
        "org_email": DEMO_ORG_EMAIL,
        "principal_fingerprint": principal_key.public.fingerprint,
        "already_present": "true" if already else "false",
    }


def _ensure_participant(service: BureauService, admin: Auth, name: str, org_type: str, key_name: str, token: str, scopes: list[str]) -> dict:
    existing = service.repo.key_by_hash(token_hash(token))
    if existing is not None:
        org = service.repo.get_org(existing["org_id"])
        if org is None:
            raise RuntimeError("demo key has no organization")
        return org
    org = service.create_org(admin, name, org_type)
    _known_key(service, org["org_id"], key_name, token, scopes)
    return org


def _known_key(service: BureauService, org_id: str, name: str, token: str, scopes: list[str]) -> None:
    prefix = token.removeprefix("gab_")
    service.repo.create_key(
        {
            "key_id": "key_" + prefix,
            "org_id": org_id,
            "name": name,
            "prefix": prefix,
            "secret_hash": token_hash(token),
            "scopes": scopes,
            "created_at": service.stamp(),
            "revoked_at": None,
            "rotated_from": None,
        }
    )


def main() -> None:
    import argparse
    import json

    from kata_service.bureau import BureauService, HttpWebhookSender
    from kata_service.bureau_pg import PostgresRepo
    from kata_service.settings import settings_from_env

    parser = argparse.ArgumentParser(description="Apply the bureau schema and optionally insert demo data.")
    parser.add_argument("--demo", action="store_true", help="Insert the public demo organizations and agent.")
    args = parser.parse_args()
    settings = settings_from_env()
    if not settings.database_url:
        raise SystemExit("DATABASE_URL is not set. Start the service with GAB_DEMO=1 to use the in-memory demo.")
    repo = PostgresRepo(settings.database_url, settings.schema_url)
    repo.migration_versions()
    if not args.demo:
        print("schema applied")
        return
    from kata_service.store import open_store

    service = BureauService(
        repo,
        log_store=open_store(settings.database_url, settings.schema_url),
        log_key=demo_settings(settings).log_key(),
        sender=HttpWebhookSender(),
        dev_mailbox=False,
    )
    print(json.dumps(seed_demo(service), indent=2))


if __name__ == "__main__":
    main()
