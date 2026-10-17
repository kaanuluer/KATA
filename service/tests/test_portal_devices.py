# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Passkeys, the installable portal, and step-up approvals. Memory only."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from urllib.parse import urlparse

import pytest

from kata_intent.values import hash_document
from kata_service.bureau import BureauError
from kata_service.passkeys import CHALLENGE_TTL_SECONDS, PUSH_TEXT, deliver_web_push
from kata_service.settings import settings_from_env

from soft_passkey import SoftPasskey, assertion_for, bind_device, origin_of
from test_bureau import _action, _agreement, _auth, _client, _key, _org, _register


def test_the_flag_defaults_off_and_the_push_sentence_is_fixed():
    assert settings_from_env({}).step_up_approval is False
    assert settings_from_env({"GAB_STEP_UP_APPROVAL": "1"}).step_up_approval is True
    assert settings_from_env({"GAB_STEP_UP_TTL_SECONDS": "5000"}).approval_ttl_seconds == 900
    with pytest.raises(BureauError, match="push text is fixed"):
        deliver_web_push(
            {"endpoint": "https://push.example/device"},
            "merchant techstore amount 1300 shopper-01",
            public_key="pub",
            private_key="priv",
            subject=None,
        )
    assert (
        deliver_web_push(
            {"endpoint": "https://push.example/device"},
            PUSH_TEXT,
            public_key=None,
            private_key=None,
            subject=None,
        )
        == "not_configured"
    )


def test_portal_is_installable_and_states_what_is_stored():
    client = _client()
    portal = client.get("/portal")
    assert "public half of the passkey" in portal.text
    assert "explicit consent" in portal.text
    assert "does not score individuals" in portal.text
    script = client.get("/assets/portal.js").text
    assert "agent.score" not in script
    assert "portal-score" not in script
    manifest = client.get("/manifest.webmanifest")
    assert manifest.status_code == 200
    body = manifest.json()
    assert body["start_url"] == "/portal"
    assert body["display"] == "standalone"
    assert body["short_name"] == "GAB"
    assert {item["sizes"] for item in body["icons"]} >= {"192x192", "512x512"}
    for name in ("gab-icon-192.png", "gab-icon-512.png"):
        icon = client.get(f"/assets/{name}")
        assert icon.status_code == 200
        assert icon.headers["content-type"].startswith("image/png")
        assert icon.content[:8] == b"\x89PNG\r\n\x1a\n"
    worker = client.get("/sw.js")
    assert worker.status_code == 200
    assert "The portal is offline" in worker.text
    assert "Nothing new is stored" in worker.text
    assert "/v1/" in worker.text
    assert PUSH_TEXT not in worker.text
    assert "techstore" not in worker.text


def test_passkey_sign_in_lists_and_removes_a_device_and_keeps_the_email_link():
    client = _portal_client()
    token = _portal_token(client)
    soft = bind_device(client, token, "Phone")
    listed = client.get("/v1/portal/devices", headers=_auth(token))
    assert listed.status_code == 200
    assert listed.json()["devices"][0]["label"] == "Phone"
    assert listed.json()["individual_score"] is False
    assert "public half of the passkey" in json.dumps(listed.json()["stored"])
    assert "auth_secret" not in listed.text
    options = client.post("/v1/portal/passkeys/authenticate/options")
    assert options.status_code == 200
    signed = client.post(
        "/v1/portal/passkeys/authenticate",
        json={"credential": soft.authentication(options.json(), origin_of(client))},
    )
    assert signed.status_code == 200, signed.text
    assert signed.json()["kind"] == "portal"
    again = client.get("/v1/portal/agents", headers=_auth(signed.json()["token"]))
    assert again.status_code == 200
    assert "score" not in again.json()[0]
    removed = client.post(
        f"/v1/portal/devices/{listed.json()['devices'][0]['credential_id']}/remove",
        headers=_auth(token),
        json={"assertion": assertion_for(client, token, soft)},
    )
    assert removed.status_code == 200
    empty = client.get("/v1/portal/devices", headers=_auth(token))
    assert empty.json()["devices"] == []
    client.post("/v1/portal/magic-link", json={"email": "owner@example.com"})
    link = client.post("/v1/sessions", json={"token": client.app.state.bureau.dev_mailbox[-1]["token"]})
    assert link.status_code == 200
    assert link.json()["principal_id"] == "prn_owner"


def test_portal_offers_passkey_enrollment_without_naming_an_account():
    client = _client()
    portal = client.get("/portal")
    assert portal.status_code == 200
    assert 'id="portal-account"' in portal.text
    assert "Create a passkey on this device" in portal.text
    assert "Email me a sign-in link" in portal.text
    assert "No passkey was found for this device" in portal.text
    assert 'autocomplete="username webauthn"' in portal.text
    assert "Sign in with passkey" in portal.text
    script = client.get("/assets/portal.js").text
    assert "passkeyHintsSupported" in script
    assert "parseRequestOptionsFromJSON" in script
    assert 'if (passkeyHintsSupported()) next.hints = ["client-device"]' in script
    assert 'mediation: "conditional"' in script
    assert "isConditionalMediationAvailable" in script
    assert "delete next.hints" in script
    assert '"hybrid"' not in script
    assert "cross-platform" not in script
    assert "console.log" not in script
    assert "owner@example.com" not in script
    css = client.get("/assets/app.css").text
    assert "passkey-miss" in css


def test_registration_requires_a_session_and_prefers_this_device():
    client = _portal_client()
    origin = origin_of(client)
    host = urlparse(origin).hostname
    anon = client.post("/v1/portal/passkeys/register/options")
    assert anon.status_code == 401
    assert anon.json()["error"] == "credentials are required"
    assert "owner@example.com" not in anon.text
    refused = client.post("/v1/portal/passkeys/register/options", headers=_auth(client.operator_key))
    assert refused.status_code == 401
    assert refused.json()["error"] == "portal session is required"
    assert list(refused.json()) == ["error"]
    bare = client.post("/v1/portal/passkeys", json={"label": "Mac", "credential": {"id": "not-a-passkey"}})
    assert bare.status_code == 401
    assert "public_key" not in bare.text
    token = _portal_token(client)
    options = client.post("/v1/portal/passkeys/register/options", headers=_auth(token))
    assert options.status_code == 200, options.text
    body = options.json()
    assert body["rp"]["id"] == host
    assert body["rp"]["id"] != "globalagentbureau.com"
    selection = body["authenticatorSelection"]
    assert selection["authenticatorAttachment"] == "platform"
    assert selection["residentKey"] == "required"
    assert selection["requireResidentKey"] is True
    assert selection["userVerification"] == "preferred"
    assert "hints" not in body
    assert "allowCredentials" not in body
    assert "@" not in options.text
    assert "challenge" in body
    stored = _challenges(client, "register")
    assert stored
    remaining = _seconds_until(stored[-1]["expires_at"])
    assert CHALLENGE_TTL_SECONDS - 30 < remaining <= CHALLENGE_TTL_SECONDS
    sign_in = client.post("/v1/portal/passkeys/authenticate/options")
    discovered = sign_in.json()
    assert discovered["rpId"] == host
    assert "allowCredentials" not in discovered
    assert discovered["userVerification"] == "preferred"
    assert "hints" not in discovered
    assert "@" not in sign_in.text


def test_sign_in_stays_discoverable_and_failures_do_not_identify_an_account():
    client = _portal_client()
    token = _portal_token(client)
    soft = bind_device(client, token, "Mac")
    listed = client.get("/v1/portal/devices", headers=_auth(token))
    credential_id = listed.json()["devices"][0]["credential_id"]
    options = client.post("/v1/portal/passkeys/authenticate/options")
    assert options.status_code == 200
    assert "allowCredentials" not in options.json()
    assert credential_id not in options.text
    assert "owner@example.com" not in options.text
    assert "public_key" not in options.text
    proof = soft.authentication(options.json(), origin_of(client))
    unknown = dict(proof)
    unknown["id"] = "AAAA"
    unknown["rawId"] = "AAAA"
    missing = client.post("/v1/portal/passkeys/authenticate", json={"credential": unknown})
    assert missing.status_code == 401
    assert missing.json() == {"error": "passkey is not valid"}
    assert "AAAA" not in missing.text
    assert "owner@" not in missing.text
    assert options.json()["challenge"] not in missing.text
    signed = client.post("/v1/portal/passkeys/authenticate", json={"credential": proof})
    assert signed.status_code == 200, signed.text
    replay = client.post("/v1/portal/passkeys/authenticate", json={"credential": proof})
    assert replay.status_code == 401
    assert replay.json() == {"error": "passkey challenge is not valid"}
    assert "owner@" not in replay.text
    assert proof["response"]["signature"] not in replay.text
    fresh = client.post("/v1/portal/passkeys/authenticate/options")
    challenge = fresh.json()["challenge"]
    expired_proof = soft.authentication(fresh.json(), origin_of(client))
    for item in _challenges(client, "authenticate"):
        if item["challenge"] == challenge and not item.get("used_at"):
            item["expires_at"] = "2000-01-01T00:00:00Z"
    expired = client.post("/v1/portal/passkeys/authenticate", json={"credential": expired_proof})
    assert expired.status_code == 401
    assert expired.json() == {"error": "passkey challenge is not valid"}
    assert challenge not in expired.text
    step = client.post("/v1/portal/passkeys/assert/options", headers=_auth(token))
    assert step.status_code == 200, step.text
    assert step.json()["allowCredentials"]
    assert step.json()["userVerification"] == "required"
    assert step.json()["rpId"] == urlparse(origin_of(client)).hostname
    assert "hints" not in step.json()


def test_preferred_verification_accepts_enrollment_and_step_up_still_requires_it():
    client = _portal_client()
    token = _portal_token(client)
    origin = origin_of(client)
    options = client.post("/v1/portal/passkeys/register/options", headers=_auth(token))
    soft = SoftPasskey()
    saved = client.post(
        "/v1/portal/passkeys",
        headers=_auth(token),
        json={"label": "Mac", "credential": soft.registration(options.json(), origin, verified=False)},
    )
    assert saved.status_code == 200, saved.text
    assert saved.json()["label"] == "Mac"
    assert "public_key" not in saved.text
    sign_in = client.post("/v1/portal/passkeys/authenticate/options")
    opened = client.post(
        "/v1/portal/passkeys/authenticate",
        json={"credential": soft.authentication(sign_in.json(), origin, verified=False)},
    )
    assert opened.status_code == 200, opened.text
    weak = client.post("/v1/portal/passkeys/assert/options", headers=_auth(token))
    refused = client.post(
        f"/v1/portal/devices/{saved.json()['credential_id']}/remove",
        headers=_auth(token),
        json={"assertion": soft.authentication(weak.json(), origin, verified=False)},
    )
    assert refused.status_code == 401
    assert refused.json() == {"error": "passkey is not valid"}
    assert "owner@" not in refused.text
    removed = client.post(
        f"/v1/portal/devices/{saved.json()['credential_id']}/remove",
        headers=_auth(token),
        json={"assertion": assertion_for(client, token, soft)},
    )
    assert removed.status_code == 200, removed.text


def test_push_needs_consent_and_step_up_stays_off_by_default():
    client = _portal_client()
    token = _portal_token(client)
    refused = client.post(
        "/v1/portal/push",
        headers=_auth(token),
        json={"consent": False, "endpoint": "https://push.example/device", "keys": {"p256dh": "abc", "auth": "def"}},
    )
    assert refused.status_code == 400
    assert refused.json()["error"] == "push registration needs consent"
    quiet = client.get("/v1/portal/approvals", headers=_auth(token))
    assert quiet.status_code == 404
    assert quiet.json()["error"] == "step-up approval is off"
    _second_agreement(client)
    stepped = client.post("/v1/verify", headers=_auth(client.merchant_key), json={"agent_id": "shopper-01", "action": _action(10, "act_step")})
    assert stepped.json()["verdict"] == "STEP_UP"
    assert client.app.state.bureau.push_outbox == []
    assert client.app.state.bureau.repo.approvals == {}


def test_step_up_approval_is_single_use_short_lived_and_generic():
    client = _portal_client(step_up_approval=True)
    token = _portal_token(client)
    soft = bind_device(client, token)
    stored = client.post(
        "/v1/portal/push",
        headers=_auth(token),
        json={"consent": True, "endpoint": "https://push.example/device", "keys": {"p256dh": "abc", "auth": "def"}},
    )
    assert stored.status_code == 200
    assert "auth_secret" not in stored.text
    _second_agreement(client)
    action = _action(10, "act_step")
    stepped = client.post("/v1/verify", headers=_auth(client.merchant_key), json={"agent_id": "shopper-01", "action": action})
    assert stepped.json()["verdict"] == "STEP_UP"
    assert stepped.json()["reasons"] == ["AGREEMENT_NOT_SELECTED"]
    outbox = client.app.state.bureau.push_outbox
    assert len(outbox) == 1
    assert outbox[0]["body"] == PUSH_TEXT
    assert "techstore" not in outbox[0]["body"]
    assert "shopper" not in outbox[0]["body"]
    assert "10" not in outbox[0]["body"]
    waiting = client.get("/v1/portal/approvals", headers=_auth(token))
    assert waiting.status_code == 200
    assert waiting.json()[0]["action"]["context"]["merchant"] == "techstore.example"
    approval_id = waiting.json()[0]["approval_id"]
    other = _portal_token(client, email="other@example.com")
    hidden = client.get("/v1/portal/approvals", headers=_auth(other))
    assert hidden.json() == []
    bare = client.post(f"/v1/portal/approvals/{approval_id}/approve", headers=_auth(token), json={})
    assert bare.status_code == 401
    approved = client.post(
        f"/v1/portal/approvals/{approval_id}/approve",
        headers=_auth(token),
        json={"assertion": assertion_for(client, token, soft)},
    )
    assert approved.status_code == 200, approved.text
    assert approved.json()["status"] == "approved"
    again = client.post(
        f"/v1/portal/approvals/{approval_id}/approve",
        headers=_auth(token),
        json={"assertion": assertion_for(client, token, soft)},
    )
    assert again.status_code == 409
    cleared = client.get("/v1/portal/approvals", headers=_auth(token))
    assert cleared.json()[0]["status"] == "approved"
    assert "action" not in cleared.json()[0]
    second = _action(12, "act_other")
    client.post("/v1/verify", headers=_auth(client.merchant_key), json={"agent_id": "shopper-01", "action": second})
    rows = client.get("/v1/portal/approvals", headers=_auth(token)).json()
    pending = next(item for item in rows if item["status"] == "pending")
    assert pending["action"]["action_id"] == "act_other"
    assert hash_document(second) != hash_document(action)
    record = client.app.state.bureau.repo.approvals[pending["approval_id"]]
    record["expires_at"] = "2000-01-01T00:00:00Z"
    expired = client.post(
        f"/v1/portal/approvals/{pending['approval_id']}/reject",
        headers=_auth(token),
        json={"assertion": assertion_for(client, token, soft)},
    )
    assert expired.status_code == 410
    fresh = _action(14, "act_reject")
    client.post("/v1/verify", headers=_auth(client.merchant_key), json={"agent_id": "shopper-01", "action": fresh})
    pending = next(item for item in client.get("/v1/portal/approvals", headers=_auth(token)).json() if item["status"] == "pending")
    rejected = client.post(
        f"/v1/portal/approvals/{pending['approval_id']}/reject",
        headers=_auth(token),
        json={"assertion": assertion_for(client, token, soft)},
    )
    assert rejected.status_code == 200
    assert rejected.json()["status"] == "rejected"
    dispute = client.post(
        "/v1/portal/disputes",
        headers=_auth(token),
        json={"report_id": "rpt_missing", "statement": "No.", "assertion": assertion_for(client, token, soft)},
    )
    assert dispute.status_code == 404


def _challenges(client, kind: str) -> list[dict]:
    rows = [item for item in client.app.state.bureau.repo.challenges.values() if item["kind"] == kind]
    return sorted(rows, key=lambda item: item["expires_at"])


def _seconds_until(stamp: str) -> float:
    expiry = datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    return (expiry - datetime.now(timezone.utc)).total_seconds()


def _portal_client(**overrides):
    client = _client(dev_mailbox=True, **overrides)
    operator = _org(client, "Harbor Agents", "agent_operator")
    merchant = _org(client, "Techstore", "merchant")
    client.operator_key = _key(client, operator["org_id"])
    client.merchant_key = _key(client, merchant["org_id"])
    _register(client, client.operator_key, principal_id="prn_owner", principal_email="owner@example.com")
    filed = client.post(
        "/v1/agents/shopper-01/intents",
        headers=_auth(client.operator_key),
        content=_agreement("prn_owner").to_json(),
    )
    assert filed.status_code == 200, filed.text
    return client


def _second_agreement(client) -> None:
    filed = client.post(
        "/v1/agents/shopper-01/intents",
        headers=_auth(client.operator_key),
        content=_agreement("prn_owner", intent_id="int_other", agreement_id="agr_other").to_json(),
    )
    assert filed.status_code == 200, filed.text


def _portal_token(client, email: str = "owner@example.com") -> str:
    client.post("/v1/portal/magic-link", json={"email": email})
    token = client.app.state.bureau.dev_mailbox[-1]["token"]
    session = client.post("/v1/sessions", json={"token": token})
    assert session.status_code == 200, session.text
    return session.json()["token"]
