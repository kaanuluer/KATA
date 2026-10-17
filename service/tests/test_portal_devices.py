# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Passkeys and the installable individual portal. Memory only."""

from __future__ import annotations

import json

from soft_passkey import assertion_for, bind_device, origin_of
from test_bureau import _agreement, _auth, _client, _key, _org, _register


def test_portal_is_installable_and_states_what_is_stored():
    client = _client()
    portal = client.get("/portal")
    assert "public half of the passkey" in portal.text
    assert "Session tokens are stored as hashes." in portal.text
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
    assert "an agent is waiting for your approval" not in worker.text
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


def _portal_token(client, email: str = "owner@example.com") -> str:
    client.post("/v1/portal/magic-link", json={"email": email})
    token = client.app.state.bureau.dev_mailbox[-1]["token"]
    session = client.post("/v1/sessions", json={"token": token})
    assert session.status_code == 200, session.text
    return session.json()["token"]
