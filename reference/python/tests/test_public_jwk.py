# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: Apache-2.0
"""Public JWK member allow-list.

SYNTHETIC TEST DATA. Keys are generated in the test process and are not credentials.
"""

from __future__ import annotations

import pytest

from kata_intent import KataError, generate_keypair, public_key_from_jwk


def _public(algorithm: str) -> dict:
    return generate_keypair(algorithm).public.to_jwk()


def test_unknown_jwk_member_is_rejected():
    jwk = _public("EdDSA")
    jwk["ext"] = False
    with pytest.raises(KataError, match="JWK member is not allowed: ext"):
        public_key_from_jwk(jwk)

    several = _public("ES256")
    several["x5c"] = ["SYNTHETIC"]
    several["ext"] = True
    with pytest.raises(KataError, match="JWK member is not allowed: ext, x5c"):
        public_key_from_jwk(several)


def test_allowed_jwk_members_are_accepted():
    ed = _public("EdDSA")
    ed.update({"alg": "EdDSA", "use": "sig", "key_ops": ["verify"]})
    loaded = public_key_from_jwk(ed)
    assert loaded.algorithm == "EdDSA"
    assert loaded.fingerprint == ed["kid"]

    ec = _public("ES256")
    ec.update({"alg": "ES256", "use": "sig", "key_ops": ["verify"]})
    loaded_ec = public_key_from_jwk(ec)
    assert loaded_ec.algorithm == "ES256"
    assert loaded_ec.fingerprint == ec["kid"]

    minimal = {"kty": ed["kty"], "crv": ed["crv"], "x": ed["x"]}
    assert public_key_from_jwk(minimal).fingerprint == ed["kid"]


def test_use_key_ops_and_alg_values_are_checked():
    ed = _public("EdDSA")
    bad_use = dict(ed)
    bad_use["use"] = "enc"
    with pytest.raises(KataError, match="JWK use must be sig"):
        public_key_from_jwk(bad_use)

    bad_ops = dict(ed)
    bad_ops["key_ops"] = ["verify", "sign"]
    with pytest.raises(KataError, match="subset"):
        public_key_from_jwk(bad_ops)

    not_a_list = dict(ed)
    not_a_list["key_ops"] = "verify"
    with pytest.raises(KataError, match="subset"):
        public_key_from_jwk(not_a_list)

    empty_ops = dict(ed)
    empty_ops["key_ops"] = []
    assert public_key_from_jwk(empty_ops).algorithm == "EdDSA"

    wrong_alg = dict(ed)
    wrong_alg["alg"] = "ES256"
    with pytest.raises(KataError, match="JWK alg does not match the key type"):
        public_key_from_jwk(wrong_alg)

    ec = _public("ES256")
    swapped = dict(ec)
    swapped["alg"] = "EdDSA"
    with pytest.raises(KataError, match="JWK alg does not match the key type"):
        public_key_from_jwk(swapped)


def test_private_jwk_is_still_rejected():
    jwk = _public("EdDSA")
    jwk["d"] = "SYNTHETIC"
    with pytest.raises(KataError, match="refusing a private JWK"):
        public_key_from_jwk(jwk)

    both = _public("ES256")
    both["d"] = "SYNTHETIC"
    both["ext"] = True
    with pytest.raises(KataError, match="refusing a private JWK"):
        public_key_from_jwk(both)
