# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: Apache-2.0
"""The seven decisions Kaan made after the first intent-agreement draft."""

from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from kata_intent import (
    DailyTableRates,
    InstitutionDirectory,
    KataError,
    Policy,
    RevocationCache,
    TransparencyLog,
    generate_keypair,
)
from kata_intent.agreement import Agreement
from kata_intent.institutions import DEFAULT_GRACE_SECONDS, well_known_url
from kata_intent.revocation import sign_revocation_push, verify_inclusion
from kata_intent.values import prefixed_hash

from conftest import AT, EXPIRY, NOW, activate, bound_eval, propose, purchase

import pytest

ROOT = Path(__file__).resolve().parents[3] / "schemas"


def _loads(name: str) -> dict:
    return json.loads((ROOT / name).read_text())


def _registry(*names: str) -> Registry:
    resources = [(_loads(name)["$id"], Resource.from_contents(_loads(name))) for name in names]
    return Registry().with_resources(resources)


def _header_alg(signature: dict) -> str:
    padded = signature["protected"] + "=" * (-len(signature["protected"]) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))["alg"]


def test_ed25519_and_es256_both_verify(principal_key, agent_key):
    eddsa = activate(principal_key, agent_key)
    assert eddsa.mandate["algorithm"] == "EdDSA"
    assert _header_alg(eddsa.mandate["signature"]) == "EdDSA"
    assert bound_eval(eddsa, principal_key, agent_key).verdict == "ALLOW"

    es256 = generate_keypair("ES256")
    signed = activate(es256, agent_key, agreement_id="agr_es256")
    assert signed.mandate["algorithm"] == "ES256"
    assert _header_alg(signed.mandate["signature"]) == "ES256"
    assert bound_eval(signed, es256, agent_key).verdict == "ALLOW"
    Draft202012Validator(_loads("agreement.json"), registry=_registry("intent.json", "intent-mandate.json", "agreement.json")).validate(
        json.loads(signed.to_json())
    )


def test_ledger_truncation_mismatch_staleness_and_tamper(principal_key, agent_key):
    agreement = activate(principal_key, agent_key)
    agreement.record_allowed(purchase(action_id="act_old", amount=100))
    agreement.record_allowed(purchase(action_id="act_older", amount=50))
    assert agreement.ledger[1]["prev_entry_hash"] == agreement.ledger[0]["entry_hash"]

    truncated = bound_eval(
        agreement,
        principal_key,
        agent_key,
        purchase(action_id="act_next", amount=100),
        ledger_sequence=1,
    )
    assert truncated.verdict == "DENY"
    assert "LEDGER_TRUNCATED" in truncated.reasons

    mismatch = bound_eval(
        agreement,
        principal_key,
        agent_key,
        purchase(action_id="act_next", amount=100),
        ledger_head="sha256:" + "ab" * 32,
    )
    assert "LEDGER_HEAD_MISMATCH" in mismatch.reasons

    missing = bound_eval(
        agreement,
        principal_key,
        agent_key,
        purchase(action_id="act_next", amount=100),
        ledger_sequence=None,
    )
    assert "LEDGER_HEAD_MISSING" in missing.reasons

    stale = bound_eval(
        agreement,
        principal_key,
        agent_key,
        purchase(action_id="act_next", amount=100),
        ledger_as_of=AT,
    )
    assert stale.verdict == "STEP_UP"
    assert "LEDGER_STALE" in stale.reasons

    fresh = bound_eval(agreement, principal_key, agent_key, purchase(action_id="act_next", amount=100))
    assert "LEDGER_STALE" not in fresh.reasons
    assert "CUMULATIVE_LIMIT_EXCEEDED" not in fresh.reasons

    tampered = agreement.to_dict()
    tampered["ledger"][0]["amount"] = 1
    broken = bound_eval(tampered, principal_key, agent_key, purchase(action_id="act_next", amount=100))
    assert "LEDGER_TAMPERED" in broken.reasons


def test_pull_cache_push_and_transparency_log(principal_key, agent_key):
    agreement = activate(principal_key, agent_key, agreement_id="agr_rev")
    before = agreement.to_json()
    revocation = agreement.revoke(principal_key, "2026-10-04T18:00:00Z")
    live = Agreement.from_json(before)

    fetches = {"count": 0}

    def fetcher():
        fetches["count"] += 1
        return [revocation]

    cache = RevocationCache(fetcher)
    first = bound_eval(live, principal_key, agent_key, revocation_cache=cache)
    second = bound_eval(
        live,
        principal_key,
        agent_key,
        revocation_cache=cache,
        now="2026-10-04T14:06:11Z",
        ledger_as_of="2026-10-04T14:06:11Z",
    )
    assert first.verdict == "DENY"
    assert "MANDATE_REVOKED" in first.reasons
    assert second.verdict == "DENY"
    assert fetches["count"] == 1
    third = bound_eval(
        live,
        principal_key,
        agent_key,
        revocation_cache=cache,
        now="2026-10-04T14:08:11Z",
        ledger_as_of="2026-10-04T14:08:11Z",
    )
    assert fetches["count"] == 2
    assert "MANDATE_REVOKED" in third.reasons

    named = activate(
        principal_key,
        agent_key,
        agreement_id="agr_endpoint",
        revocation_endpoint="https://example.test/kata/revocations/agr_endpoint",
    )
    empty = RevocationCache(lambda: [])
    checked = bound_eval(named, principal_key, agent_key, revocation_cache=empty)
    assert checked.verdict == "ALLOW"
    assert empty.fetches == 1

    notifier = generate_keypair()
    notice = sign_revocation_push(revocation, notifier, NOW)
    pushed = bound_eval(live, principal_key, agent_key, revocation_pushes=[notice], push_notifier_key=notifier.public)
    assert "MANDATE_REVOKED" in pushed.reasons
    forged = bound_eval(
        live,
        principal_key,
        agent_key,
        revocation_pushes=[{"at": NOW, "kata_revocation_push": "1"}],
        push_notifier_key=notifier.public,
    )
    assert "REVOCATION_PUSH_INVALID" in forged.reasons

    log_key = generate_keypair()
    log = TransparencyLog()
    log.append("agreement", {"agreement_id": live.agreement_id})
    log.append("revocation", revocation)
    assert log.verify_chain()
    assert TransparencyLog().root() == prefixed_hash(b"")
    proof = log.inclusion_proof(2)
    assert verify_inclusion(log.entries[1]["entry_hash"], 1, proof, log.root())
    head = log.sign_tree_head(log_key, NOW)
    Draft202012Validator(_loads("transparency-log.json")).validate(head)
    logged = bound_eval(
        live,
        principal_key,
        agent_key,
        transparency_log=log,
        tree_head=head,
        tree_head_key=log_key.public,
    )
    assert "MANDATE_REVOKED" in logged.reasons

    bad_head = dict(head)
    bad_head["root"] = "sha256:" + "cd" * 32
    invalid = bound_eval(
        live,
        principal_key,
        agent_key,
        transparency_log=log,
        tree_head=bad_head,
        tree_head_key=log_key.public,
    )
    assert "TREE_HEAD_INVALID" in invalid.reasons

    log.entries[1]["body"] = {"agreement_id": "agr_rev", "reason": "altered"}
    tampered = bound_eval(
        live,
        principal_key,
        agent_key,
        transparency_log=log,
        tree_head=head,
        tree_head_key=log_key.public,
    )
    assert "TRANSPARENCY_LOG_TAMPERED" in tampered.reasons


def test_unscoped_ceiling_uses_a_daily_fx_rate(principal_key, agent_key):
    wide = _unscoped(principal_key, agent_key, "agr_fx", maximum_amount=50000)
    rates = DailyTableRates({("CAD", "USD", "2026-10-04"): "0.75"})
    over = bound_eval(wide, principal_key, agent_key, policy=Policy(unscoped_amount_ceiling=10000, fx_rates=rates))
    assert over.verdict == "STEP_UP"
    assert "OVER_BROAD_INTENT" in over.reasons

    small = _unscoped(principal_key, agent_key, "agr_fx_small", maximum_amount=100)
    under = bound_eval(small, principal_key, agent_key, purchase(amount=50), policy=Policy(unscoped_amount_ceiling=10000, fx_rates=rates))
    assert under.verdict == "ALLOW"

    missing = bound_eval(wide, principal_key, agent_key, policy=Policy(unscoped_amount_ceiling=10000))
    assert missing.verdict == "STEP_UP"
    assert "FX_RATE_UNAVAILABLE" in missing.reasons
    assert "OVER_BROAD_INTENT" not in missing.reasons

    off = bound_eval(wide, principal_key, agent_key, policy=Policy())
    assert off.verdict == "ALLOW"

    usd = _unscoped(principal_key, agent_key, "agr_usd", currency="USD", maximum_amount=50000)
    same = bound_eval(usd, principal_key, agent_key, purchase(currency="USD", amount=10), policy=Policy(unscoped_amount_ceiling=10000))
    assert "OVER_BROAD_INTENT" in same.reasons


def test_institution_keys_allowlist_well_known_and_grace(principal_key, agent_key, merchant_key):
    assert DEFAULT_GRACE_SECONDS == 7 * 24 * 3600
    assert well_known_url("https://issuer.example/ignored") == "https://issuer.example/.well-known/kata-keys.json"
    document = {"keys": [{"public_key": merchant_key.public.to_jwk(), "not_after": "2026-10-01T00:00:00Z"}]}
    Draft202012Validator(
        _loads("institution-keys.json"),
        registry=_registry("intent.json", "intent-mandate.json"),
    ).validate(document)

    trusted = _acknowledged(principal_key, agent_key, merchant_key, "agr_allow")
    allowlist = InstitutionDirectory(allowlist={"mer_techstore": [{"public_key": merchant_key.public.to_jwk()}]})
    assert bound_eval(trusted, principal_key, agent_key, institution_directory=allowlist).verdict == "ALLOW"

    published = _acknowledged(principal_key, agent_key, merchant_key, "agr_well_known")
    directory = InstitutionDirectory(
        allowlist={"mer_techstore": [{"domain": "techstore.example"}]},
        well_known=lambda domain: document if domain == "techstore.example" else {"keys": []},
    )
    assert bound_eval(published, principal_key, agent_key, institution_directory=directory).verdict == "ALLOW"

    unknown = _acknowledged(principal_key, agent_key, merchant_key, "agr_unknown")
    stranger = InstitutionDirectory(allowlist={"mer_techstore": [{"public_key": generate_keypair().public.to_jwk()}]})
    rejected = bound_eval(unknown, principal_key, agent_key, institution_directory=stranger)
    assert rejected.verdict == "DENY"
    assert "INSTITUTION_KEY_UNTRUSTED" in rejected.reasons

    rotated = _acknowledged(principal_key, agent_key, merchant_key, "agr_grace")
    within = InstitutionDirectory(
        allowlist={"mer_techstore": [{"public_key": merchant_key.public.to_jwk(), "not_after": "2026-10-01T00:00:00Z"}]}
    )
    assert bound_eval(rotated, principal_key, agent_key, institution_directory=within).verdict == "ALLOW"
    expired = InstitutionDirectory(
        allowlist={"mer_techstore": [{"public_key": merchant_key.public.to_jwk(), "not_after": "2026-10-01T00:00:00Z"}]},
        grace_seconds=24 * 3600,
    )
    past = bound_eval(rotated, principal_key, agent_key, institution_directory=expired)
    assert "INSTITUTION_KEY_UNTRUSTED" in past.reasons
    with pytest.raises(KataError, match="grace"):
        InstitutionDirectory(grace_seconds=-1)


def _unscoped(principal_key, agent_key, agreement_id, **intent_overrides):
    intent = {
        "allowed_actions": ["purchase"],
        "currency": "CAD",
        "intent_id": "int_open",
        "maximum_amount": 50000,
        "merchant_constraints": [],
        "purpose": "purchase",
        "time_limit": EXPIRY,
        "version": 1,
    }
    intent.update(intent_overrides)
    return activate(
        principal_key,
        agent_key,
        agreement_id=agreement_id,
        intent=intent,
        limits={"cumulative_maximum": 100000},
    )


def _acknowledged(principal_key, agent_key, merchant_key, agreement_id):
    agreement = propose(principal_key, agent_key, agreement_id=agreement_id, required_acknowledgements=["merchant"])
    agreement.accept(principal_key, AT, confirmed_text=agreement.rendering_preview())
    agreement.acknowledge(
        role="merchant",
        party_id="mer_techstore",
        private_key=merchant_key,
        at="2026-10-04T13:59:00Z",
    )
    return agreement


def test_replica_older_than_sixty_seconds_steps_up(principal_key, agent_key):
    agreement = activate(principal_key, agent_key)
    moment = datetime(2026, 10, 4, 14, 2, 11, tzinfo=timezone.utc)
    fresh = bound_eval(
        agreement,
        principal_key,
        agent_key,
        ledger_as_of=moment - timedelta(seconds=60),
        policy=Policy(max_ledger_staleness_seconds=60),
    )
    assert fresh.verdict == "ALLOW"
    late = bound_eval(
        agreement,
        principal_key,
        agent_key,
        ledger_as_of=moment - timedelta(seconds=61),
        policy=Policy(max_ledger_staleness_seconds=60),
    )
    assert late.verdict == "STEP_UP"
    assert "LEDGER_STALE" in late.reasons
