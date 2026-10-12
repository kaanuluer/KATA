# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: Apache-2.0
"""Reference library for KATA intent agreements.

Concept / open design. Not production ready. The authoritative description
is ``docs/intent-agreement.md`` in the KATA repository.
"""

from kata_intent.agreement import Actor, Agreement
from kata_intent.errors import KataError
from kata_intent.evaluate import Evaluation, LedgerEntry, Policy, evaluate
from kata_intent.keys import (
    PrivateKey,
    PublicKey,
    generate_keypair,
    private_key_from_seed,
    public_key_from_jwk,
)
from kata_intent.render import render_mandate

__version__ = "0.1.0"
__all__ = [
    "Actor",
    "Agreement",
    "Evaluation",
    "KataError",
    "LedgerEntry",
    "Policy",
    "PrivateKey",
    "PublicKey",
    "evaluate",
    "generate_keypair",
    "private_key_from_seed",
    "public_key_from_jwk",
    "render_mandate",
]
