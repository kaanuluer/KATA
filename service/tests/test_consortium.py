# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Fingerprint sightings shared across consortium members."""

from __future__ import annotations

from kata_service.settings import settings_from_env

from test_bureau import _auth, _client, _key, _org


FINGERPRINT = "sha256:" + "c3" * 32


def test_match_hides_the_count_until_two_other_members():
    client = _client()
    merchant = _org(client, "Techstore", "merchant")
    wallet = _org(client, "Northwind Wallet", "wallet")
    bank = _org(client, "Harbor Bank", "bank_issuer")
    merchant_key = _key(client, merchant["org_id"])
    wallet_key = _key(client, wallet["org_id"])
    bank_key = _key(client, bank["org_id"])
    refused = client.post(
        "/v1/consortium/sightings",
        headers=_auth(merchant_key),
        json={"fingerprint": FINGERPRINT},
    )
    assert refused.status_code == 403
    first = _join(client, merchant["org_id"])
    again = _join(client, merchant["org_id"])
    assert again["member_id"] == first["member_id"]
    _join(client, wallet["org_id"])
    _join(client, bank["org_id"])
    sighting = client.post(
        "/v1/consortium/sightings",
        headers=_auth(merchant_key),
        json={"fingerprint": FINGERPRINT},
    )
    assert sighting.status_code == 200, sighting.text
    assert set(sighting.json()) == {"sighting_id", "fingerprint", "seen_at"}
    repeat = client.post(
        "/v1/consortium/sightings",
        headers=_auth(merchant_key),
        json={"fingerprint": FINGERPRINT},
    )
    assert repeat.json()["sighting_id"] == sighting.json()["sighting_id"]
    alone = client.post("/v1/consortium/match", headers=_auth(merchant_key), json={"fingerprint": FINGERPRINT})
    assert alone.status_code == 200
    assert alone.json() == {"matched": False}
    client.post("/v1/consortium/sightings", headers=_auth(wallet_key), json={"fingerprint": FINGERPRINT})
    one_other = client.post("/v1/consortium/match", headers=_auth(merchant_key), json={"fingerprint": FINGERPRINT})
    assert one_other.json() == {"matched": False}
    assert "other_member_count" not in one_other.json()
    client.post("/v1/consortium/sightings", headers=_auth(bank_key), json={"fingerprint": FINGERPRINT})
    matched = client.post("/v1/consortium/match", headers=_auth(merchant_key), json={"fingerprint": FINGERPRINT})
    assert matched.json() == {"matched": True, "other_member_count": 2}
    assert "Techstore" not in matched.text
    assert "agent_id" not in matched.json()
    assert "org_id" not in matched.json()
    bad = client.post("/v1/consortium/match", headers=_auth(merchant_key), json={"fingerprint": "sha256:abcd"})
    assert bad.status_code == 400


def test_threshold_of_one_returns_the_count():
    assert settings_from_env({}).consortium_match_threshold == 2
    assert settings_from_env({"GAB_CONSORTIUM_MATCH_THRESHOLD": "1"}).consortium_match_threshold == 1
    client = _client(consortium_match_threshold=1)
    left = _org(client, "Left", "merchant")
    right = _org(client, "Right", "wallet")
    left_key = _key(client, left["org_id"])
    right_key = _key(client, right["org_id"])
    _join(client, left["org_id"])
    _join(client, right["org_id"])
    client.post("/v1/consortium/sightings", headers=_auth(left_key), json={"fingerprint": FINGERPRINT})
    client.post("/v1/consortium/sightings", headers=_auth(right_key), json={"fingerprint": FINGERPRINT})
    matched = client.post("/v1/consortium/match", headers=_auth(left_key), json={"fingerprint": FINGERPRINT})
    assert matched.json() == {"matched": True, "other_member_count": 1}


def _join(client, org_id: str) -> dict:
    response = client.post(
        "/v1/admin/consortium/members",
        headers=_auth("admin-test-token"),
        json={"org_id": org_id},
    )
    assert response.status_code == 200, response.text
    return response.json()
