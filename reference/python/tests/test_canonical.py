# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: Apache-2.0

from decimal import Decimal

from kata_intent.canonical import canonical_bytes


def test_object_keys_sort_and_numbers_have_one_encoding():
    encoded = canonical_bytes({"b": 1, "a": Decimal("1.50"), "c": Decimal("1500")})
    assert encoded == b'{"a":1.5,"b":1,"c":1500}'


def test_strings_escape_line_separators():
    encoded = canonical_bytes({"s": "a\u2028b"})
    assert encoded == b'{"s":"a\\u2028b"}'
