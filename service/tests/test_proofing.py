# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Identity proofing caps a verification claim at the evidence on file."""

from __future__ import annotations

from kata_service.defenses import ScorePolicy, effective_assurance
from kata_service.settings import settings_from_env

from test_bureau import _auth, _client, _key, _org, _register


REVIEW = "sha256:" + "a1" * 32
INSTITUTION = "sha256:" + "b2" * 32


def test_effective_assurance_caps_the_claim():
    assert effective_assurance("operator_verified", {"key_binding"}, require_proofing=True) == "key_bound"
    assert effective_assurance("operator_verified", {"key_binding", "operator_review"}, require_proofing=True) == "operator_verified"
    assert (
        effective_assurance(
            "institution_attested",
            {"key_binding", "operator_review", "institution_attestation"},
            require_proofing=True,
        )
        == "institution_attested"
    )
    assert effective_assurance("institution_attested", {"operator_review"}, require_proofing=True) == "operator_verified"
    assert effective_assurance("unverified", {"key_binding"}, require_proofing=True) == "unverified"
    assert effective_assurance("operator_verified", set(), require_proofing=False) == "operator_verified"


def test_proofing_flag_stays_on_when_other_defenses_are_off():
    assert settings_from_env({}).score_policy.require_proofing is True
    assert settings_from_env({"GAB_DEFENSES": "0"}).score_policy.require_proofing is True
    assert settings_from_env({"GAB_REQUIRE_PROOFING": "0"}).score_policy.require_proofing is False
    assert settings_from_env({"GAB_REQUIRE_PROOFING": "yes"}).score_policy.require_proofing is True


def test_operator_claim_without_evidence_scores_as_key_bound():
    client = _client()
    operator = _org(client, "Harbor Agents", "agent_operator")
    merchant = _org(client, "Techstore", "merchant")
    operator_key = _key(client, operator["org_id"])
    merchant_key = _key(client, merchant["org_id"])
    registered = _register(client, operator_key)
    assert registered["verification_level"] == "operator_verified"
    assert registered["assurance_level"] == "key_bound"
    assert registered["score"] == 620
    assert {item["method"] for item in registered["proofings"]} == {"key_binding"}
    hidden = client.get("/v1/agents/shopper-01", headers=_auth(merchant_key))
    assert hidden.status_code == 200
    assert "proofings" not in hidden.json()
    assert hidden.json()["assurance_level"] == "key_bound"


def test_operator_review_and_institution_attestation_raise_assurance():
    client = _client()
    operator = _org(client, "Harbor Agents", "agent_operator")
    wallet = _org(client, "Northwind Wallet", "wallet")
    merchant = _org(client, "Techstore", "merchant")
    operator_key = _key(client, operator["org_id"])
    wallet_key = _key(client, wallet["org_id"])
    merchant_key = _key(client, merchant["org_id"])
    _register(client, operator_key)
    reviewed = client.post(
        "/v1/agents/shopper-01/proofing",
        headers=_auth(operator_key),
        json={"method": "operator_review", "evidence_hash": REVIEW},
    )
    assert reviewed.status_code == 200, reviewed.text
    assert reviewed.json()["assurance_level"] == "operator_verified"
    assert reviewed.json()["score"] == 700
    attested = client.post("/v1/agents/shopper-01/attest", headers=_auth(wallet_key))
    assert attested.status_code == 200
    assert attested.json()["verification_level"] == "institution_attested"
    assert attested.json()["assurance_level"] == "operator_verified"
    assert attested.json()["score"] == 700
    raised = client.post(
        "/v1/agents/shopper-01/proofing",
        headers=_auth(wallet_key),
        json={"method": "institution_attestation", "evidence_hash": INSTITUTION},
    )
    assert raised.status_code == 200, raised.text
    assert raised.json()["assurance_level"] == "institution_attested"
    assert raised.json()["score"] == 780
    again = client.post(
        "/v1/agents/shopper-01/proofing",
        headers=_auth(wallet_key),
        json={"method": "institution_attestation", "evidence_hash": INSTITUTION},
    )
    assert again.status_code == 200
    assert again.json()["proofing"]["evidence_hash"] == INSTITUTION
    listed = client.get("/v1/agents/shopper-01", headers=_auth(operator_key)).json()
    institution_rows = [item for item in listed["proofings"] if item["method"] == "institution_attestation"]
    assert len(institution_rows) == 1
    assert again.json()["proofing"]["proofing_id"] == institution_rows[0]["proofing_id"]
    assert client.post(
        "/v1/agents/shopper-01/proofing",
        headers=_auth(operator_key),
        json={"method": "institution_attestation", "evidence_hash": INSTITUTION},
    ).status_code == 403
    assert client.post(
        "/v1/agents/shopper-01/proofing",
        headers=_auth(merchant_key),
        json={"method": "operator_review", "evidence_hash": REVIEW},
    ).status_code == 403
    assert client.post(
        "/v1/agents/shopper-01/proofing",
        headers=_auth(operator_key),
        json={"method": "key_binding", "evidence_hash": REVIEW},
    ).status_code == 400
    assert client.post(
        "/v1/agents/shopper-01/proofing",
        headers=_auth(operator_key),
        json={"method": "operator_review", "evidence_hash": "not-a-hash"},
    ).status_code == 400


def test_proofing_gate_off_uses_the_claim():
    client = _client(score_policy=ScorePolicy(require_proofing=False))
    operator = _org(client, "Harbor Agents", "agent_operator")
    operator_key = _key(client, operator["org_id"])
    registered = _register(client, operator_key)
    assert registered["verification_level"] == "operator_verified"
    assert registered["assurance_level"] == "operator_verified"
    assert registered["score"] == 700
