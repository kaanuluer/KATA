# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""RFC 9421 signature base and Ed25519 verification.

The signature base is the strict serialization from RFC 9421 section 2.5.
``ed25519`` is the HTTP signature algorithm name. The public key is Ed25519.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Mapping
from urllib.parse import parse_qsl, urlsplit

from kata_intent.keys import PublicKey

from kata_service.evidence.structured_fields import (
    InnerList,
    Item,
    StructuredFieldError,
    parse_dictionary,
    parse_item,
    serialize_inner_list,
    serialize_item,
    serialize_member,
)

_FOLD = re.compile(r"\r?\n[ \t]+")
_FORM_SAFE = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789*-._")
_MAX_FIELD = 16384
WELL_KNOWN_DIRECTORY = "/.well-known/http-message-signatures-directory"


class HttpSignatureError(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass
class HttpMessage:
    method: str = ""
    path: str = ""
    authority: str = ""
    query: str = ""
    scheme: str = "https"
    status: int | None = None
    headers: list[tuple[str, str]] = field(default_factory=list)

    def field_values(self, name: str) -> list[str] | None:
        lowered = name.lower()
        if not any(header == lowered for header, _value in self.headers):
            return None
        return [value for header, value in self.headers if header == lowered]


def message_from_material(material: Mapping[str, object]) -> HttpMessage:
    method = material.get("method") if isinstance(material.get("method"), str) else ""
    path = material.get("path") if isinstance(material.get("path"), str) else ""
    authority = material.get("authority") if isinstance(material.get("authority"), str) else ""
    scheme = material.get("scheme") if isinstance(material.get("scheme"), str) else "https"
    query = material.get("query") if isinstance(material.get("query"), str) else ""
    if query.startswith("?"):
        query = query[1:]
    status = material.get("status")
    status_code = status if isinstance(status, int) and not isinstance(status, bool) else None
    headers = _headers(material.get("headers"))
    return HttpMessage(
        method=method,
        path=path,
        authority=authority,
        query=query,
        scheme=scheme.lower(),
        status=status_code,
        headers=headers,
    )


def _headers(value: object) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    if value is None:
        return rows
    if isinstance(value, Mapping):
        pairs = value.items()
    elif isinstance(value, list):
        pairs = []
        for item in value:
            if not isinstance(item, (list, tuple)) or len(item) != 2 or not isinstance(item[0], str):
                raise HttpSignatureError("malformed")
            pairs.append((item[0], item[1]))
    else:
        raise HttpSignatureError("malformed")
    for name, raw in pairs:
        if not isinstance(name, str) or not name or len(name) > 128:
            raise HttpSignatureError("malformed")
        values = raw if isinstance(raw, list) else [raw]
        for item in values:
            if not isinstance(item, str) or len(item) > _MAX_FIELD:
                raise HttpSignatureError("malformed")
            rows.append((name.lower(), item))
    return rows


def header_text(message: HttpMessage, name: str) -> str | None:
    values = message.field_values(name)
    if values is None:
        return None
    return canonical_field(values)


def canonical_field(values: list[str]) -> str:
    cleaned: list[str] = []
    for value in values:
        text = _FOLD.sub(" ", value).strip(" \t")
        if not text.isascii() or "\n" in text or "\r" in text:
            raise HttpSignatureError("malformed")
        cleaned.append(text)
    return ", ".join(cleaned)


def signature_material(message: HttpMessage, *, label: str | None = None) -> tuple[str, bytes, InnerList, str]:
    """Return the signature base, raw signature, parameters, and label."""

    signature_input = header_text(message, "signature-input")
    signature = header_text(message, "signature")
    if signature_input is None or signature is None:
        raise HttpSignatureError("malformed")
    if len(signature_input) > _MAX_FIELD or len(signature) > _MAX_FIELD:
        raise HttpSignatureError("malformed")
    try:
        inputs = parse_dictionary(signature_input)
        signatures = parse_dictionary(signature)
    except StructuredFieldError as exc:
        raise HttpSignatureError("malformed") from exc
    chosen_label = _label(inputs, signatures, label)
    covered = dict(inputs)[chosen_label]
    signed = dict(signatures)[chosen_label]
    if not isinstance(covered, InnerList) or not isinstance(signed, Item):
        raise HttpSignatureError("malformed")
    if signed.params or not isinstance(signed.value, bytes):
        raise HttpSignatureError("malformed")
    if len(covered.items) > 32:
        raise HttpSignatureError("malformed")
    base = signature_base(message, covered)
    return base, signed.value, covered, chosen_label


def verify_ed25519(message: HttpMessage, public_key: PublicKey, *, label: str | None = None) -> bool:
    try:
        base, raw, _covered, _label_name = signature_material(message, label=label)
    except HttpSignatureError:
        return False
    if public_key.algorithm != "EdDSA" or len(raw) != 64:
        return False
    try:
        return public_key.verify(base.encode("ascii"), raw)
    except UnicodeEncodeError:
        return False


def signature_base(message: HttpMessage, covered: InnerList) -> str:
    lines: list[str] = []
    seen: set[str] = set()
    for component in covered.items:
        if not isinstance(component, Item) or not isinstance(component.value, str) or not component.value:
            raise HttpSignatureError("malformed")
        identifier = serialize_item(component)
        if identifier in seen:
            raise HttpSignatureError("malformed")
        seen.add(identifier)
        value = component_value(message, component)
        lines.append(f"{identifier}: {value}")
    lines.append('"@signature-params": ' + serialize_inner_list(covered))
    # Covered lines end in LF. The @signature-params line does not (RFC 9421 ABNF).
    covered_lines = lines[:-1]
    base = ("\n".join(covered_lines) + "\n" if covered_lines else "") + lines[-1]
    if not base.isascii():
        raise HttpSignatureError("malformed")
    return base


def component_value(message: HttpMessage, item: Item) -> str:
    name = item.value
    if not isinstance(name, str):
        raise HttpSignatureError("malformed")
    params = _param_map(item.params)
    if name.startswith("@"):
        return _derived(message, name, params)
    return _field(message, name, params)


def _param_map(params: list[tuple[str, object]]) -> dict[str, object]:
    mapped: dict[str, object] = {}
    for key, value in params:
        if key in mapped:
            raise HttpSignatureError("malformed")
        mapped[key] = value
    return mapped


def _derived(message: HttpMessage, name: str, params: dict[str, object]) -> str:
    if name == "@query-param":
        if set(params) != {"name"} or not isinstance(params.get("name"), str):
            raise HttpSignatureError("missing_component")
        return query_param(message.query, str(params["name"]))
    if params:
        raise HttpSignatureError("missing_component")
    if name == "@method":
        if not message.method or not message.method.isascii() or any(char.isspace() for char in message.method):
            raise HttpSignatureError("missing_component")
        return message.method
    if name == "@path":
        if not message.path.startswith("/") or not message.path.isascii() or any(char.isspace() for char in message.path):
            raise HttpSignatureError("missing_component")
        return message.path
    if name == "@query":
        if not message.query:
            return "?"
        if not message.query.isascii() or any(char.isspace() for char in message.query):
            raise HttpSignatureError("malformed")
        return "?" + message.query
    if name == "@authority":
        return normalized_authority(message)
    if name == "@scheme":
        if message.scheme not in {"http", "https"}:
            raise HttpSignatureError("missing_component")
        return message.scheme
    if name == "@request-target":
        if not message.path.startswith("/"):
            raise HttpSignatureError("missing_component")
        if not message.query:
            return message.path
        return f"{message.path}?{message.query}"
    if name == "@target-uri":
        authority = normalized_authority(message)
        path = message.path if message.path.startswith("/") else ""
        if not path:
            raise HttpSignatureError("missing_component")
        target = path if not message.query else f"{path}?{message.query}"
        return f"{message.scheme}://{authority}{target}"
    if name == "@status":
        if message.status is None:
            raise HttpSignatureError("missing_component")
        return str(message.status)
    raise HttpSignatureError("missing_component")


def _field(message: HttpMessage, name: str, params: dict[str, object]) -> str:
    if set(params) - {"sf", "key", "bs", "req", "tr"}:
        raise HttpSignatureError("missing_component")
    if params.get("req") is True or params.get("tr") is True or params.get("bs") is True:
        raise HttpSignatureError("missing_component")
    if "sf" in params and params["sf"] is not True:
        raise HttpSignatureError("missing_component")
    if "key" in params:
        if not isinstance(params["key"], str) or not params["key"]:
            raise HttpSignatureError("missing_component")
        return dictionary_member(message, name, str(params["key"]))
    if params.get("sf") is True:
        raise HttpSignatureError("missing_component")
    values = message.field_values(name)
    if values is None:
        raise HttpSignatureError("missing_component")
    return canonical_field(values)


def dictionary_member(message: HttpMessage, name: str, member_key: str) -> str:
    values = message.field_values(name)
    if not values:
        raise HttpSignatureError("missing_component")
    if name == "signature-agent" and len(values) == 1:
        text = canonical_field(values)
        if text.startswith('"'):
            return _legacy_agent_member(text, member_key)
    found: list[str] = []
    try:
        for value in values:
            for key, member in parse_dictionary(canonical_field([value])):
                if key == member_key:
                    found.append(serialize_member(member))
    except StructuredFieldError as exc:
        raise HttpSignatureError("missing_component") from exc
    if len(found) != 1:
        raise HttpSignatureError("missing_component")
    return found[0]


def _legacy_agent_member(text: str, member_key: str) -> str:
    del member_key
    try:
        item = parse_item(text)
    except StructuredFieldError as exc:
        raise HttpSignatureError("missing_component") from exc
    if item.params or not isinstance(item.value, str) or not item.value:
        raise HttpSignatureError("missing_component")
    return serialize_item(item)


def query_param(query: str, name: str) -> str:
    try:
        pairs = parse_qsl(query, keep_blank_values=True, strict_parsing=False, encoding="utf-8", errors="strict")
    except ValueError as exc:
        raise HttpSignatureError("missing_component") from exc
    encoded = [(_form_encode(key), _form_encode(value)) for key, value in pairs]
    matches = [value for key, value in encoded if key == name]
    if len(matches) != 1:
        raise HttpSignatureError("missing_component")
    result = matches[0]
    if not result.isascii():
        raise HttpSignatureError("malformed")
    return result


def _form_encode(text: str) -> str:
    parts: list[str] = []
    for byte in text.encode("utf-8"):
        if byte in _FORM_SAFE:
            parts.append(chr(byte))
        else:
            parts.append(f"%{byte:02X}")
    return "".join(parts)


def normalized_authority(message: HttpMessage) -> str:
    raw = message.authority.strip()
    if not raw:
        host = header_text(message, "host")
        if not host:
            raise HttpSignatureError("missing_component")
        raw = host
    return normalize_authority(raw, message.scheme)


def normalize_authority(authority: str, scheme: str) -> str:
    if not authority or not authority.isascii() or any(char.isspace() for char in authority):
        raise HttpSignatureError("malformed")
    parsed = urlsplit("//" + authority)
    host = parsed.hostname
    if not host:
        raise HttpSignatureError("malformed")
    host = host.lower()
    display = f"[{host}]" if ":" in host else host
    port = parsed.port
    default = 443 if scheme == "https" else 80 if scheme == "http" else None
    if port is None or port == default:
        return display
    return f"{display}:{port}"


def agent_directory(message: HttpMessage, label: str) -> str:
    """Resolve Signature-Agent to the JWKS directory URL."""

    values = message.field_values("signature-agent")
    if not values:
        raise HttpSignatureError("malformed")
    text = canonical_field(values)
    if text.startswith('"'):
        try:
            item = parse_item(text)
        except StructuredFieldError as exc:
            raise HttpSignatureError("malformed") from exc
        if item.params or not isinstance(item.value, str):
            raise HttpSignatureError("malformed")
        return directory_url(item.value)
    try:
        members = parse_dictionary(text)
    except StructuredFieldError as exc:
        raise HttpSignatureError("malformed") from exc
    chosen = None
    for key, member in members:
        if key != label:
            continue
        if not isinstance(member, Item) or member.params or not isinstance(member.value, str):
            raise HttpSignatureError("malformed")
        chosen = member.value
        break
    if chosen is None:
        raise HttpSignatureError("malformed")
    return directory_url(chosen)


def directory_url(url: str) -> str:
    """HTTPS directory for a Signature-Agent value.

    An origin (no path, or ``/``) publishes the well-known directory. Any other
    path is fetched as given. The query is not part of the identifier.
    """

    if not isinstance(url, str) or not url or len(url) > 200 or not url.isascii():
        raise HttpSignatureError("malformed")
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.username or parsed.password or parsed.fragment or not parsed.hostname:
        raise HttpSignatureError("directory_url_rejected")
    host = parsed.hostname.lower()
    display = f"[{host}]" if ":" in host else host
    port = parsed.port
    netloc = display if port in (None, 443) else f"{display}:{port}"
    path = parsed.path or ""
    if path in {"", "/"}:
        path = WELL_KNOWN_DIRECTORY
    if not path.startswith("/") or "\\" in path:
        raise HttpSignatureError("directory_url_rejected")
    resolved = f"https://{netloc}{path}"
    if len(resolved) > 200:
        raise HttpSignatureError("malformed")
    return resolved


def _label(
    inputs: list[tuple[str, Item | InnerList]],
    signatures: list[tuple[str, Item | InnerList]],
    requested: str | None,
) -> str:
    input_keys = [key for key, _value in inputs]
    signature_keys = {key for key, _value in signatures}
    if requested is not None:
        if requested not in input_keys or requested not in signature_keys:
            raise HttpSignatureError("malformed")
        return requested
    common = [key for key in input_keys if key in signature_keys]
    if len(common) == 1:
        return common[0]
    tagged = []
    looked = dict(inputs)
    for key in common:
        member = looked[key]
        if isinstance(member, InnerList):
            for name, value in member.params:
                if name == "tag" and value == "web-bot-auth":
                    tagged.append(key)
    if len(tagged) == 1:
        return tagged[0]
    raise HttpSignatureError("malformed")


def covers_authority(covered: InnerList) -> bool:
    for item in covered.items:
        if isinstance(item, Item) and item.value in {"@authority", "@target-uri"} and not item.params:
            return True
    return False


def covers_signature_agent(covered: InnerList, label: str) -> bool:
    for item in covered.items:
        if not isinstance(item, Item) or item.value != "signature-agent":
            continue
        params = _param_map(item.params)
        if not params:
            return True
        if set(params) == {"key"} and params.get("key") == label:
            return True
    return False


def parameter(covered: InnerList, name: str) -> object:
    found = [value for key, value in covered.params if key == name]
    if not found:
        return None
    if len(found) > 1:
        raise HttpSignatureError("malformed")
    return found[0]
