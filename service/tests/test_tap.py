# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Visa Trusted Agent Protocol evidence. Synthetic keys only.

The vector in tests/fixtures/tap/vector.json is an Ed25519 signature over the
RFC 9421 signature base. The seed label is not a credential. No directory is
contacted. GAB_TAP_VERIFY defaults off, and POST /v1/verify stays on the
existing golden bytes.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from kata_intent.keys import private_key_from_seed

from kata_service.bureau import BureauService, MemoryRepo
from kata_service.evidence.http_sig import message_from_material, signature_material
from kata_service.evidence.schema import payload_hash
from kata_service.evidence.store import MemoryEvidenceStore
from kata_service.evidence.verifier import verifier_for
from kata_service.settings import settings_from_env
from test_decision_rationale import CASES, FIXTURES, _action, _case, _client, _ready, _verify

FIXTURE = Path(__file__).parent / "fixtures" / "tap" / "vector.json"
NOW = datetime(2026, 11, 28, 12, 0, tzinfo=timezone.utc)


def _doc() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def _material() -> dict:
    return copy.deepcopy(_doc()["material"])


def _keys(**overrides) -> list[dict]:
    key = dict(_doc()["key"])
    key.update(overrides)
    return [key]


def _check(material: dict, now: datetime = NOW, keys: list[dict] | None = None, store: MemoryEvidenceStore | None = None):
    store = store or MemoryEvidenceStore()
    verifier = verifier_for("tap", store, tap_verify=True, tap_keys=keys if keys is not None else _keys())
    return verifier.verify(material, now=now), store


def _private():
    label = _doc()["seed_label"]
    return private_key_from_seed(hashlib.sha256(label.encode("ascii")).digest())


def _resign(tag: str, nonce: str) -> dict:
    doc = _doc()
    material = _material()
    params = (
        f'("@authority" "@path");created={doc["created"]};expires={doc["expires"]};'
        f'keyid="{doc["key"]["key_id"]}";alg="ed25519";nonce="{nonce}";tag="{tag}"'
    )
    material["headers"]["signature-input"] = f"sig1={params}"
    material["headers"]["signature"] = "sig1=:" + base64.b64encode(b"\x00" * 64).decode("ascii") + ":"
    base, _raw, _covered, _label = signature_material(message_from_material(material))
    signed = base64.b64encode(_private().sign(base.encode("ascii"))).decode("ascii")
    material["headers"]["signature"] = f"sig1=:{signed}:"
    return material


def test_synthetic_vector_verifies_and_both_tags_are_accepted():
    doc = _doc()
    private = _private()
    assert base64.b64encode(private.public.raw).decode("ascii") == doc["key"]["public_key"]
    assert int(NOW.timestamp()) == doc["created"]
    material = doc["material"]
    base, raw, _covered, label = signature_material(message_from_material(material))
    assert label == "sig1"
    assert private.public.verify(base.encode("ascii"), raw) is True
    evidence, store = _check(material)
    assert evidence["result"] == "valid"
    assert evidence["reason"] == "ok"
    assert evidence["source"] == "tap"
    assert evidence["key_id"] == "synthetic-ed25519"
    assert evidence["subject"] == "synthetic-ed25519"
    assert evidence["issuer"] == "https://agent.example"
    assert evidence["claims"]["tag"] == "agent-payer-auth"
    assert evidence["claims"]["alg"] == "ed25519"
    assert evidence["claims"]["created"] == doc["created"]
    assert evidence["claims"]["expires"] == doc["expires"]
    assert evidence["payload_hash"] == payload_hash(base.encode("ascii"))
    assert "probability" not in evidence
    browser, _browser_store = _check(_resign("agent-browser-auth", "tap-nonce-browser-01"))
    assert browser["result"] == "valid"
    assert browser["reason"] == "ok"
    assert browser["claims"]["tag"] == "agent-browser-auth"
    assert store.consume_nonce("tap", "tap-nonce-synthetic-01", now=NOW, expires_at=NOW) is False


def test_rejects_wrong_and_missing_tag():
    wrong = _material()
    wrong["headers"]["signature-input"] = wrong["headers"]["signature-input"].replace(
        'tag="agent-payer-auth"',
        'tag="agent-payment-auth"',
    )
    evidence, _store = _check(wrong)
    assert evidence["result"] == "invalid"
    assert evidence["reason"] == "tag"
    missing = _material()
    missing["headers"]["signature-input"] = missing["headers"]["signature-input"].replace(
        ';tag="agent-payer-auth"',
        "",
    )
    evidence, _store = _check(missing)
    assert evidence["result"] == "invalid"
    assert evidence["reason"] == "tag"


def test_rejects_nonce_replay():
    store = MemoryEvidenceStore()
    first, _store = _check(_material(), store=store)
    second, _store = _check(_material(), store=store)
    assert first["result"] == "valid"
    assert first["reason"] == "ok"
    assert second["result"] == "invalid"
    assert second["reason"] == "replay"
    assert second["claims"] == {}


def test_rejects_signatures_outside_the_created_expires_window():
    doc = _doc()
    created = doc["created"]
    expires = doc["expires"]
    early = datetime.fromtimestamp(created - 61, timezone.utc)
    evidence, store = _check(_material(), now=early)
    assert evidence["result"] == "invalid"
    assert evidence["reason"] == "not_yet_valid"
    recovered, _store = _check(_material(), now=NOW, store=store)
    assert recovered["result"] == "valid"
    late = datetime.fromtimestamp(expires + 1, timezone.utc)
    evidence, store = _check(_material(), now=late)
    assert evidence["result"] == "invalid"
    assert evidence["reason"] == "expired"
    at_expiry = datetime.fromtimestamp(expires, timezone.utc)
    allowed, _store = _check(_resign("agent-payer-auth", "tap-nonce-at-expiry"), now=at_expiry)
    assert allowed["result"] == "valid"
    skew = datetime.fromtimestamp(created - 60, timezone.utc)
    on_skew, _store = _check(_resign("agent-payer-auth", "tap-nonce-skew"), now=skew)
    assert on_skew["result"] == "valid"
    assert on_skew["reason"] == "ok"


def test_rejects_bad_signature():
    material = _material()
    encoded = material["headers"]["signature"].removeprefix("sig1=:").removesuffix(":")
    raw = bytearray(base64.b64decode(encoded))
    raw[-1] ^= 0x01
    material["headers"]["signature"] = "sig1=:" + base64.b64encode(bytes(raw)).decode("ascii") + ":"
    evidence, store = _check(material)
    assert evidence["result"] == "invalid"
    assert evidence["reason"] == "signature"
    recovered, _store = _check(_material(), store=store)
    assert recovered["result"] == "valid"


def test_rejects_unknown_key_id():
    material = _material()
    material["headers"]["signature-input"] = material["headers"]["signature-input"].replace(
        'keyid="synthetic-ed25519"',
        'keyid="missing-key"',
    )
    evidence, store = _check(material)
    assert evidence["result"] == "invalid"
    assert evidence["reason"] == "unknown_key"
    assert evidence["key_id"] == "missing-key"
    recovered, _store = _check(_material(), store=store)
    assert recovered["result"] == "valid"
    inactive, _store = _check(_material(), keys=_keys(is_active="false"))
    assert inactive["result"] == "invalid"
    assert inactive["reason"] == "inactive_key"


def test_other_algorithm_and_visa_keyid_spelling_are_rejected():
    rsa = _material()
    rsa["headers"]["signature-input"] = rsa["headers"]["signature-input"].replace(
        'alg="ed25519"',
        'alg="rsa-pss-sha256"',
    )
    evidence, _store = _check(rsa)
    assert evidence["result"] == "invalid"
    assert evidence["reason"] == "alg_rejected"
    camel = _material()
    camel["headers"]["signature-input"] = camel["headers"]["signature-input"].replace(
        'keyid="synthetic-ed25519"',
        'keyId="synthetic-ed25519"',
    )
    evidence, _store = _check(camel)
    assert evidence["result"] == "invalid"
    assert evidence["reason"] == "malformed"


def test_flag_off_leaves_verify_on_the_golden_bytes():
    assert settings_from_env({}).tap_verify is False
    assert settings_from_env({"GAB_TAP_VERIFY": "0"}).tap_verify is False
    assert settings_from_env({"GAB_TAP_VERIFY": "1"}).tap_verify is True
    assert settings_from_env({"GAB_TAP_VERIFY": "yes"}).tap_verify is True
    assert BureauService(MemoryRepo()).tap_verify is False
    published = json.dumps([_doc()["key"]])
    assert settings_from_env({"GAB_TAP_KEYS": published}).tap_keys == ()
    loaded = settings_from_env({"GAB_TAP_VERIFY": "1", "GAB_TAP_KEYS": published})
    assert loaded.tap_keys[0]["key_id"] == "synthetic-ed25519"
    assert "d" not in loaded.tap_keys[0]
    assert settings_from_env({"GAB_TAP_VERIFY": "1", "GAB_TAP_KEYS": "not-json"}).tap_keys == ()
    private = dict(_doc()["key"], d="not-a-key")
    assert settings_from_env({"GAB_TAP_VERIFY": "1", "GAB_TAP_KEYS": json.dumps([private])}).tap_keys == ()
    for name, ready, body in CASES:
        _held, response = _case(name, ready, body)
        assert _held.app.state.settings.tap_verify is False
        assert response.content == (FIXTURES / f"{name}.bin").read_bytes()
    signed = {
        "agent_id": "shopper-01",
        "action": _action("act_allow"),
        "external_evidence": _material(),
    }
    client, response = _case("allow", {}, signed)
    assert response.content == (FIXTURES / "allow.bin").read_bytes()
    _held, flagged = _case(
        "allow",
        {},
        {"agent_id": "shopper-01", "action": _action("act_allow")},
        tap_verify=True,
    )
    assert flagged.content == (FIXTURES / "allow.bin").read_bytes()
    del client


def test_flag_off_does_not_verify_tap_and_flag_on_does_not_change_the_decision():
    plain = {"agent_id": "shopper-01", "action": _action("act_tap_plain")}
    _baseline, baseline = _case("allow", {}, plain)
    client = _client(evidence_verifier=True, tap_verify=False)
    token = _ready(client)
    ignored = _verify(client, token, {**plain, "external_evidence": _material()})
    assert ignored.content == baseline.content
    row = client.app.state.bureau._evidence_store.list_evidence()[-1]
    assert row["evidence"]["source"] == "tap"
    assert row["evidence"]["result"] == "unverifiable"
    assert row["evidence"]["reason"] == "unsupported_verifier"
    assert row["kata_decision"] == "ALLOW"
    assert ignored.json()["verdict"] == "ALLOW"

    live = _client(evidence_verifier=True, tap_verify=True, tap_keys=tuple(_keys()))
    live.app.state.bureau._now = lambda: NOW
    live_token = _ready(live)
    unsigned = _verify(live, live_token, {"agent_id": "shopper-01", "action": _action("act_tap_unsigned")})
    recorded = _verify(
        live,
        live_token,
        {"agent_id": "shopper-01", "action": _action("act_tap_signed"), "external_evidence": _material()},
    )
    assert recorded.content == unsigned.content
    assert recorded.json()["verdict"] == "ALLOW"
    assert recorded.json()["kata_decision"] == "ALLOW"
    assert "probability" not in recorded.json()
    stored = live.app.state.bureau._evidence_store.list_evidence()[-1]
    assert stored["evidence"]["result"] == "valid"
    assert stored["evidence"]["reason"] == "ok"
    assert stored["kata_decision"] == "ALLOW"

    disabled = verifier_for("tap", MemoryEvidenceStore(), tap_keys=_keys())
    blocked = disabled.verify(_material(), now=NOW)
    assert blocked["result"] == "unverifiable"
    assert blocked["reason"] == "unsupported_verifier"
