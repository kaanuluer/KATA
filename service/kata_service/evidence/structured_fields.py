# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""RFC 8941 structured field parser and serializer.

Enough of the dictionary, list, item, and parameter grammar to read
``Signature-Input``, ``Signature``, and ``Signature-Agent``. Serialization is
the strict form those signatures are computed over.
"""

from __future__ import annotations

import base64

_KEY_START = frozenset("abcdefghijklmnopqrstuvwxyz*")
_KEY_CHAR = frozenset("abcdefghijklmnopqrstuvwxyz0123456789_.*-")
_TOKEN_START = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz*")
_TOKEN_CHAR = frozenset("!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz:/")


class StructuredFieldError(ValueError):
    """The field is not a valid structured field."""


class Token:
    def __init__(self, text: str) -> None:
        self.text = text

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Token) and other.text == self.text

    def __repr__(self) -> str:
        return f"Token({self.text!r})"


class DecimalValue:
    def __init__(self, text: str) -> None:
        self.text = text

    def __eq__(self, other: object) -> bool:
        return isinstance(other, DecimalValue) and other.text == self.text


class Item:
    def __init__(self, value: object, params: list[tuple[str, object]] | None = None) -> None:
        self.value = value
        self.params = list(params or [])


class InnerList:
    def __init__(self, items: list[Item], params: list[tuple[str, object]] | None = None) -> None:
        self.items = list(items)
        self.params = list(params or [])


class _Parser:
    def __init__(self, text: str) -> None:
        if not isinstance(text, str) or not text.isascii():
            raise StructuredFieldError("structured field is not ASCII")
        self.text = text
        self.i = 0
        self.n = len(text)

    def peek(self) -> str:
        if self.i >= self.n:
            return ""
        return self.text[self.i]

    def eat(self, expected: str) -> None:
        if self.peek() != expected:
            raise StructuredFieldError("structured field is malformed")
        self.i += 1

    def skip_sp(self) -> None:
        while self.peek() == " ":
            self.i += 1

    def skip_ows(self) -> None:
        # An empty peek is a substring of every string, so this does not use ``in``.
        while self.i < self.n and self.text[self.i] in " \t":
            self.i += 1

    def finished(self) -> None:
        if self.i != self.n:
            raise StructuredFieldError("structured field is malformed")

    def parse_key(self) -> str:
        if self.peek() not in _KEY_START:
            raise StructuredFieldError("structured field is malformed")
        start = self.i
        self.i += 1
        while self.peek() in _KEY_CHAR:
            self.i += 1
        return self.text[start : self.i]

    def parse_parameters(self) -> list[tuple[str, object]]:
        params: list[tuple[str, object]] = []
        seen: set[str] = set()
        while self.peek() == ";":
            self.eat(";")
            self.skip_sp()
            key = self.parse_key()
            if key in seen:
                raise StructuredFieldError("structured field is malformed")
            seen.add(key)
            if self.peek() == "=":
                self.eat("=")
                params.append((key, self.parse_bare()))
            else:
                params.append((key, True))
        return params

    def parse_bare(self) -> object:
        char = self.peek()
        if char == '"':
            return self.parse_string()
        if char == ":":
            return self.parse_binary()
        if char == "?":
            return self.parse_boolean()
        if char == "-" or char.isdigit():
            return self.parse_number()
        if char in _TOKEN_START:
            return self.parse_token()
        raise StructuredFieldError("structured field is malformed")

    def parse_string(self) -> str:
        self.eat('"')
        chars: list[str] = []
        while True:
            char = self.peek()
            if char == '"':
                self.eat('"')
                return "".join(chars)
            if char == "\\":
                self.eat("\\")
                escaped = self.peek()
                if escaped not in {'"', "\\"}:
                    raise StructuredFieldError("structured field is malformed")
                chars.append(escaped)
                self.eat(escaped)
                continue
            if not char or ord(char) < 0x20 or ord(char) > 0x7E:
                raise StructuredFieldError("structured field is malformed")
            chars.append(char)
            self.i += 1

    def parse_binary(self) -> bytes:
        self.eat(":")
        start = self.i
        while self.peek() and self.peek() != ":":
            self.i += 1
        encoded = self.text[start : self.i]
        self.eat(":")
        try:
            return base64.b64decode(encoded, validate=True)
        except Exception as exc:  # noqa: BLE001 — a bad byte sequence is a malformed field
            raise StructuredFieldError("structured field is malformed") from exc

    def parse_boolean(self) -> bool:
        self.eat("?")
        char = self.peek()
        if char not in {"0", "1"}:
            raise StructuredFieldError("structured field is malformed")
        self.eat(char)
        return char == "1"

    def parse_number(self) -> int | DecimalValue:
        start = self.i
        if self.peek() == "-":
            self.i += 1
        digits = 0
        while self.peek().isdigit():
            digits += 1
            self.i += 1
        if digits < 1:
            raise StructuredFieldError("structured field is malformed")
        if self.peek() == ".":
            if digits > 12:
                raise StructuredFieldError("structured field is malformed")
            self.i += 1
            fraction = 0
            while self.peek().isdigit():
                fraction += 1
                self.i += 1
            if fraction < 1 or fraction > 3:
                raise StructuredFieldError("structured field is malformed")
            text = self.text[start : self.i]
            _reject_leading_zero(text)
            return DecimalValue(text)
        if digits > 15:
            raise StructuredFieldError("structured field is malformed")
        text = self.text[start : self.i]
        _reject_leading_zero(text)
        if text in {"-0"}:
            raise StructuredFieldError("structured field is malformed")
        return int(text)

    def parse_token(self) -> Token:
        if self.peek() not in _TOKEN_START:
            raise StructuredFieldError("structured field is malformed")
        start = self.i
        self.i += 1
        while self.peek() in _TOKEN_CHAR:
            self.i += 1
        return Token(self.text[start : self.i])

    def parse_item(self) -> Item:
        value = self.parse_bare()
        return Item(value, self.parse_parameters())

    def parse_inner_list(self) -> InnerList:
        self.eat("(")
        self.skip_sp()
        items: list[Item] = []
        if self.peek() != ")":
            items.append(self.parse_item())
            while self.peek() == " ":
                self.skip_sp()
                if self.peek() == ")":
                    break
                items.append(self.parse_item())
        self.eat(")")
        return InnerList(items, self.parse_parameters())

    def parse_member_value(self) -> Item | InnerList:
        if self.peek() == "(":
            return self.parse_inner_list()
        return self.parse_item()

    def parse_dictionary(self) -> list[tuple[str, Item | InnerList]]:
        members: list[tuple[str, Item | InnerList]] = []
        seen: set[str] = set()
        if self.i >= self.n:
            return members
        while True:
            key = self.parse_key()
            if key in seen:
                raise StructuredFieldError("structured field is malformed")
            seen.add(key)
            if self.peek() == "=":
                self.eat("=")
                members.append((key, self.parse_member_value()))
            else:
                members.append((key, Item(True, self.parse_parameters())))
            self.skip_ows()
            if self.i >= self.n:
                return members
            self.eat(",")
            self.skip_ows()
            if self.i >= self.n:
                raise StructuredFieldError("structured field is malformed")


def _reject_leading_zero(text: str) -> None:
    body = text[1:] if text.startswith("-") else text
    integer = body.split(".", 1)[0]
    if len(integer) > 1 and integer.startswith("0"):
        raise StructuredFieldError("structured field is malformed")


def _prepare(text: str) -> _Parser:
    if not isinstance(text, str):
        raise StructuredFieldError("structured field is malformed")
    stripped = text.strip(" \t")
    return _Parser(stripped)


def parse_dictionary(text: str) -> list[tuple[str, Item | InnerList]]:
    parser = _prepare(text)
    members = parser.parse_dictionary()
    parser.finished()
    return members


def parse_item(text: str) -> Item:
    parser = _prepare(text)
    item = parser.parse_item()
    parser.finished()
    return item


def serialize_bare(value: object) -> str:
    if isinstance(value, bool):
        return "?1" if value else "?0"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
    if isinstance(value, bytes):
        return ":" + base64.b64encode(value).decode("ascii") + ":"
    if isinstance(value, Token):
        return value.text
    if isinstance(value, DecimalValue):
        return value.text
    raise StructuredFieldError("structured field is malformed")


def serialize_parameters(params: list[tuple[str, object]]) -> str:
    parts: list[str] = []
    for key, value in params:
        if value is True:
            parts.append(";" + key)
        else:
            parts.append(";" + key + "=" + serialize_bare(value))
    return "".join(parts)


def serialize_item(item: Item) -> str:
    return serialize_bare(item.value) + serialize_parameters(item.params)


def serialize_inner_list(inner: InnerList) -> str:
    body = " ".join(serialize_item(item) for item in inner.items)
    return "(" + body + ")" + serialize_parameters(inner.params)


def serialize_member(value: Item | InnerList) -> str:
    if isinstance(value, InnerList):
        return serialize_inner_list(value)
    return serialize_item(value)
