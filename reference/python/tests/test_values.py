# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: Apache-2.0

import pytest

from kata_intent.errors import KataError
from kata_intent.values import MAX_DOCUMENT_DEPTH, coerce, money


def test_money_rejects_a_non_numeric_string():
    with pytest.raises(KataError):
        money("abc")


def test_coerce_rejects_a_document_nested_past_the_limit():
    node: object = {"amount": 1}
    for _ in range(MAX_DOCUMENT_DEPTH + 2):
        node = {"down": node}
    with pytest.raises(KataError):
        coerce(node)
