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
