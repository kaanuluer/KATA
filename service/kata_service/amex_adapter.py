# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Config-driven prototype: an AmEx-style intent record and a partial KATA agreement.

Field paths live in adapters/amex/mapping.v1.json. This module does not name
AmEx fields of its own. A binding counts as verified only when the config says
so and cites a source. Every other binding is reported as assumed.
"""

from __future__ import annotations

import copy
import json
import re
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

_MISSING = object()
_DECIMAL = re.compile(r"-?\d+(\.\d+)?")
_CURRENCY = re.compile(r"^[A-Z]{3}$")
_INTEGER = re.compile(r"[1-9]\d*")


class AdapterError(Exception):
    """The record or the mapping config cannot be converted."""

    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(message)


def mapping_path() -> Path:
    """Locate adapters/amex/mapping.v1.json from the checkout that contains it."""

    here = Path(__file__).resolve()
    for candidate in (Path.cwd(), *here.parents):
        path = candidate / "adapters" / "amex" / "mapping.v1.json"
        if path.is_file():
            return path
    raise AdapterError("adapters/amex/mapping.v1.json was not found")


def load_mapping(path: Path | None = None) -> dict[str, Any]:
    raw = path if path is not None else mapping_path()
    try:
        document = json.loads(raw.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AdapterError("mapping config is not valid JSON") from exc
    if not isinstance(document, dict) or not document.get("schema_version"):
        raise AdapterError("mapping config needs schema_version")
    if not isinstance(document.get("bindings"), list):
        raise AdapterError("mapping config needs bindings")
    return document


def convert_to_kata(record: dict[str, Any], mapping: dict[str, Any] | None = None) -> dict[str, Any]:
    """Build a partial agreement envelope. Unknown AmEx fields stay on preserved.amex."""

    if not isinstance(record, dict):
        raise AdapterError("record must be a JSON object")
    config = mapping if mapping is not None else load_mapping()
    source = copy.deepcopy(record)
    agreement: dict[str, Any] = {}
    root = {"agreement": agreement}
    applied: list[dict[str, Any]] = []
    assumed: list[dict[str, Any]] = []
    verified: list[dict[str, Any]] = []
    missing: list[dict[str, Any]] = []
    consumed: set[str] = set()

    version_report = _read_schema_version(source, config, consumed, assumed, verified, missing)
    for binding in config["bindings"]:
        _apply_binding(binding, source, root, applied, assumed, verified, missing, consumed)
    for scaffold in config.get("scaffolds") or []:
        _apply_scaffold(scaffold, root, applied, assumed)
    for gap in config.get("kata_gaps") or []:
        missing.append(
            {
                "id": gap.get("id"),
                "path": gap.get("path"),
                "status": "assumed",
                "note": gap.get("note"),
            }
        )

    envelope_cfg = config.get("envelope") or {}
    envelope: dict[str, Any] = {
        "schema_version": config["schema_version"],
        "notice": config.get("notice"),
        "partial": bool(envelope_cfg.get("partial", True)),
        "compatibility_claim": envelope_cfg.get("compatibility_claim", "none"),
        "agreement": agreement,
        "preserved": {"amex": source},
        "applied": applied,
        "validation": {
            "schema_version": config["schema_version"],
            "assumed": assumed,
            "verified": verified,
            "unmapped": _unmapped(source, consumed),
            "missing": missing,
        },
    }
    if version_report is not None:
        envelope["input_schema_version"] = version_report
    return envelope


def convert_to_amex(envelope: dict[str, Any], mapping: dict[str, Any] | None = None) -> dict[str, Any]:
    """Restore an AmEx-style record from an envelope. Preserved fields are kept."""

    if not isinstance(envelope, dict):
        raise AdapterError("envelope must be a JSON object")
    preserved = (envelope.get("preserved") or {}).get("amex")
    if not isinstance(preserved, dict):
        raise AdapterError("envelope has no preserved AmEx record")
    config = mapping if mapping is not None else load_mapping()
    bindings = {item.get("id"): item for item in config.get("bindings") or []}
    restored = copy.deepcopy(preserved)
    for applied in envelope.get("applied") or []:
        binding = bindings.get(applied.get("id"))
        if not binding or not binding.get("reverse"):
            continue
        _reverse_binding(binding, applied, envelope, restored)
    return restored


def _read_schema_version(
    record: dict[str, Any],
    config: dict[str, Any],
    consumed: set[str],
    assumed: list[dict[str, Any]],
    verified: list[dict[str, Any]],
    missing: list[dict[str, Any]],
) -> Any:
    spec = config.get("input_schema_version") or {}
    field = spec.get("field")
    if not isinstance(field, str) or not field:
        return None
    status = _public_status(spec)
    if field not in record or record[field] in ("", None):
        missing.append(
            {
                "id": "input-schema-version",
                "from": field,
                "status": "assumed",
                "note": spec.get("note"),
            }
        )
        return None
    consumed.add(field)
    entry = {"id": "input-schema-version", "from": field, "status": status, "note": spec.get("note")}
    if status == "verified":
        verified.append(entry)
    else:
        assumed.append(entry)
    return record[field]


def _apply_binding(
    binding: dict[str, Any],
    source: dict[str, Any],
    root: dict[str, Any],
    applied: list[dict[str, Any]],
    assumed: list[dict[str, Any]],
    verified: list[dict[str, Any]],
    missing: list[dict[str, Any]],
    consumed: set[str],
) -> None:
    if not _when_matches(binding, source):
        return
    target = binding.get("to")
    if binding.get("when_target") == "empty" and _get_path(root, str(target)) is not _MISSING:
        return
    transform = binding.get("transform")
    status = _public_status(binding)
    if transform == "collect":
        entries = _collect(source, str(binding.get("from")))
        if not entries:
            _record_missing(binding, missing)
            return
        kata = [item["kata"] for item in entries]
        _set_path(root, str(target), kata)
        for item in entries:
            consumed.add(item["path"])
        row = _applied_row(binding, status, entries[0]["path"], kata, entries)
    else:
        raw = _get_path(source, str(binding.get("from")))
        if raw is _MISSING or raw in ("", None):
            _record_missing(binding, missing)
            return
        kata = _forward(transform, raw, binding)
        if kata is _MISSING:
            _record_missing(binding, missing)
            return
        _set_path(root, str(target), kata)
        consumed.add(str(binding.get("from")))
        row = _applied_row(binding, status, str(binding.get("from")), kata, [{"path": binding.get("from"), "source": raw, "kata": kata}])
    applied.append(row)
    listed = {"id": binding.get("id"), "from": binding.get("from"), "to": target, "status": status, "note": binding.get("note")}
    if status == "verified":
        verified.append(listed)
    else:
        assumed.append(listed)


def _apply_scaffold(
    scaffold: dict[str, Any],
    root: dict[str, Any],
    applied: list[dict[str, Any]],
    assumed: list[dict[str, Any]],
) -> None:
    required = scaffold.get("when_binding")
    if required and not any(item.get("id") == required for item in applied):
        return
    _set_path(root, str(scaffold.get("to")), copy.deepcopy(scaffold.get("value")))
    assumed.append(
        {
            "id": scaffold.get("id"),
            "to": scaffold.get("to"),
            "status": "assumed",
            "note": scaffold.get("note"),
        }
    )


def _reverse_binding(
    binding: dict[str, Any],
    applied: dict[str, Any],
    envelope: dict[str, Any],
    restored: dict[str, Any],
) -> None:
    current = _get_path(envelope, str(binding.get("to")))
    if binding.get("transform") == "collect":
        entries = applied.get("entries") or []
        if not isinstance(current, list):
            return
        original = [item.get("kata") for item in entries]
        if current == original:
            return
        for index, value in enumerate(current):
            if index < len(entries):
                path = entries[index]["path"]
                written = entries[index]["source"] if value == entries[index].get("kata") else value
            else:
                pattern = str(binding.get("from"))
                head, tail = pattern.split(".*", 1)
                tail = tail[1:] if tail.startswith(".") else tail
                path = f"{head}.{index}.{tail}" if tail else f"{head}.{index}"
                written = value
            _set_path(restored, path, written)
        return
    entries = applied.get("entries") or [{}]
    source_value = entries[0].get("source")
    kata_value = entries[0].get("kata")
    path = str(entries[0].get("path") or binding.get("from"))
    if current == kata_value or current is _MISSING:
        _set_path(restored, path, source_value)
        return
    _set_path(restored, path, _backward(binding.get("transform"), current, binding))


def _collect(source: dict[str, Any], pattern: str) -> list[dict[str, Any]]:
    if pattern.count(".*") != 1:
        raise AdapterError("collect bindings use one wildcard")
    head, tail = pattern.split(".*", 1)
    tail = tail[1:] if tail.startswith(".") else tail
    array = _get_path(source, head)
    if not isinstance(array, list):
        return []
    found: list[dict[str, Any]] = []
    for index, item in enumerate(array):
        if tail:
            if not isinstance(item, dict) or item.get(tail) in ("", None) or tail not in item:
                continue
            raw = item[tail]
            path = f"{head}.{index}.{tail}"
        else:
            raw = item
            path = f"{head}.{index}"
        kata = _forward("copy", raw, {})
        if kata is _MISSING:
            continue
        found.append({"path": path, "source": raw, "kata": kata})
    return found


def _forward(transform: Any, raw: Any, binding: dict[str, Any]) -> Any:
    if transform == "copy":
        if isinstance(raw, (str, int, float)) and not isinstance(raw, bool):
            return raw
        return _MISSING
    if transform == "suffix":
        if not isinstance(raw, str) or not raw:
            return _MISSING
        return raw + str(binding.get("suffix") or "")
    if transform == "decimal":
        number = _decimal(raw)
        if number is None:
            return _MISSING
        return int(number) if number == number.to_integral_value() else float(number)
    if transform == "integer":
        if isinstance(raw, int) and not isinstance(raw, bool) and raw >= 1:
            return raw
        if isinstance(raw, str) and _INTEGER.fullmatch(raw):
            return int(raw)
        return _MISSING
    if transform == "currency":
        if isinstance(raw, str) and _CURRENCY.fullmatch(raw):
            return raw
        return _MISSING
    raise AdapterError(f"unknown transform: {transform}")


def _backward(transform: Any, value: Any, binding: dict[str, Any]) -> Any:
    if transform == "decimal":
        number = _decimal(value)
        if number is None:
            return value
        rendered = format(number, "f")
        if "." in rendered:
            rendered = rendered.rstrip("0").rstrip(".")
        return rendered
    if transform == "integer":
        if isinstance(value, int) and not isinstance(value, bool):
            if binding.get("wire") == "string":
                return str(value)
            return value
        return value
    if transform == "suffix":
        suffix = str(binding.get("suffix") or "")
        if isinstance(value, str) and value.endswith(suffix):
            return value[: -len(suffix)] if suffix else value
        return value
    return value


def _decimal(value: Any) -> Decimal | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return Decimal(value)
    if isinstance(value, float):
        return Decimal(str(value))
    if isinstance(value, str) and _DECIMAL.fullmatch(value):
        try:
            return Decimal(value)
        except InvalidOperation:
            return None
    return None


def _public_status(binding: dict[str, Any]) -> str:
    if binding.get("status") == "verified" and isinstance(binding.get("citation"), str) and binding["citation"].startswith("https://"):
        return "verified"
    return "assumed"


def _when_matches(binding: dict[str, Any], source: dict[str, Any]) -> bool:
    clause = binding.get("when")
    if not clause:
        return True
    current = _get_path(source, str(clause.get("path")))
    return current == clause.get("equals")


def _record_missing(binding: dict[str, Any], missing: list[dict[str, Any]]) -> None:
    missing.append(
        {
            "id": binding.get("id"),
            "from": binding.get("from"),
            "to": binding.get("to"),
            "required": bool(binding.get("required")),
            "status": "assumed",
            "note": binding.get("note"),
        }
    )


def _applied_row(
    binding: dict[str, Any],
    status: str,
    path: str,
    kata: Any,
    entries: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "id": binding.get("id"),
        "status": status,
        "from": path,
        "to": binding.get("to"),
        "kata": kata,
        "entries": entries,
    }


def _unmapped(record: dict[str, Any], consumed: set[str]) -> list[dict[str, Any]]:
    rows = []
    for path, _value in _leaves(record, ""):
        if path in consumed:
            continue
        rows.append({"path": path, "status": "assumed", "disposition": "preserved"})
    return rows


def _leaves(value: Any, prefix: str):
    if isinstance(value, dict):
        if not value and prefix:
            yield prefix, value
            return
        for key, item in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            yield from _leaves(item, path)
        return
    if isinstance(value, list):
        if not value and prefix:
            yield prefix, value
            return
        for index, item in enumerate(value):
            yield from _leaves(item, f"{prefix}.{index}")
        return
    if prefix:
        yield prefix, value


def _get_path(root: Any, path: str) -> Any:
    current = root
    for segment in path.split("."):
        if isinstance(current, dict) and segment in current:
            current = current[segment]
        elif isinstance(current, list) and segment.isdigit():
            index = int(segment)
            if index < 0 or index >= len(current):
                return _MISSING
            current = current[index]
        else:
            return _MISSING
    return current


def _set_path(root: dict[str, Any], path: str, value: Any) -> None:
    current: Any = root
    segments = path.split(".")
    for index, segment in enumerate(segments):
        last = index == len(segments) - 1
        if last:
            _assign(current, segment, value)
            return
        nxt = segments[index + 1]
        child = _step(current, segment)
        want_list = nxt.isdigit()
        if want_list and not isinstance(child, list):
            child = []
            _assign(current, segment, child)
        elif not want_list and not isinstance(child, dict):
            child = {}
            _assign(current, segment, child)
        current = _step(current, segment)


def _step(current: Any, segment: str) -> Any:
    if isinstance(current, dict):
        return current.get(segment, _MISSING)
    if isinstance(current, list) and segment.isdigit():
        index = int(segment)
        if 0 <= index < len(current):
            return current[index]
    return _MISSING


def _assign(current: Any, segment: str, value: Any) -> None:
    if isinstance(current, dict):
        current[segment] = value
        return
    if isinstance(current, list) and segment.isdigit():
        index = int(segment)
        while len(current) <= index:
            current.append(None)
        current[index] = value
        return
    raise AdapterError("mapping path does not match the record shape")
