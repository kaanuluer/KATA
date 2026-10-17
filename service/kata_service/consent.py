# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Append-only consent events and the hashed notice text.

The notice files live in ``consent_text/``. A test checks that ``manifest.json``
matches the file bytes. This module does not claim legal compliance or certification.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from kata_intent.values import hash_document

_ROOT = Path(__file__).resolve().parent / "consent_text"
_PURPOSES = ("push", "network")
_HASH_FIELDS = (
    "event_id",
    "principal_id",
    "purpose",
    "granted",
    "text_version",
    "text_sha256",
    "at",
    "source_ref",
    "prev_hash",
)


class ConsentTextError(ValueError):
    """The requested notice text is not in the catalog."""


def purposes() -> tuple[str, ...]:
    return _PURPOSES


def load_manifest() -> dict[str, Any]:
    return json.loads((_ROOT / "manifest.json").read_text(encoding="utf-8"))


def text_path(purpose: str, version: str) -> Path:
    _purpose(purpose)
    if not version or "/" in version or version.startswith("."):
        raise ConsentTextError("text version is not in the catalog")
    return _ROOT / purpose / f"{version}.txt"


def file_sha256(purpose: str, version: str) -> str:
    path = text_path(purpose, version)
    if not path.is_file():
        raise ConsentTextError("text version is not in the catalog")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def current_version(purpose: str) -> str:
    _purpose(purpose)
    version = str(load_manifest().get("current", {}).get(purpose) or "")
    if not version:
        raise ConsentTextError("text version is not in the catalog")
    return version


def notice(purpose: str, version: str | None = None) -> dict[str, str]:
    chosen = version or current_version(purpose)
    digest = file_sha256(purpose, chosen)
    expected = str(load_manifest().get("sha256", {}).get(f"{purpose}/{chosen}") or "")
    if expected != digest:
        raise ConsentTextError("consent text hash does not match the manifest")
    return {"purpose": purpose, "text_version": chosen, "text_sha256": digest}


def manifest_matches_files() -> bool:
    manifest = load_manifest()
    current = manifest.get("current") or {}
    hashes = manifest.get("sha256") or {}
    if set(current) != set(_PURPOSES):
        return False
    for purpose, version in current.items():
        key = f"{purpose}/{version}"
        if hashes.get(key) != file_sha256(purpose, str(version)):
            return False
    for key, digest in hashes.items():
        purpose, _, version = str(key).partition("/")
        if not version or file_sha256(purpose, version) != digest:
            return False
    return True


def seal_event(prev_hash: str | None, fields: dict[str, Any]) -> dict[str, Any]:
    body = {
        "event_id": str(fields["event_id"]),
        "principal_id": str(fields["principal_id"]),
        "purpose": _purpose(str(fields["purpose"])),
        "granted": bool(fields["granted"]),
        "text_version": str(fields["text_version"]),
        "text_sha256": str(fields["text_sha256"]),
        "at": str(fields["at"]),
        "source_ref": str(fields.get("source_ref") or ""),
        "prev_hash": prev_hash or "",
    }
    body["entry_hash"] = hash_document({name: body[name] for name in _HASH_FIELDS})
    return body


def chain_ok(events: list[dict[str, Any]]) -> bool:
    prev = ""
    for event in events:
        sealed = seal_event(
            prev,
            {
                "event_id": event.get("event_id"),
                "principal_id": event.get("principal_id"),
                "purpose": event.get("purpose"),
                "granted": event.get("granted"),
                "text_version": event.get("text_version"),
                "text_sha256": event.get("text_sha256"),
                "at": event.get("at"),
                "source_ref": event.get("source_ref") or "",
            },
        )
        if event.get("prev_hash") != prev or event.get("entry_hash") != sealed["entry_hash"]:
            return False
        prev = str(event["entry_hash"])
    return True


def _purpose(purpose: str) -> str:
    if purpose not in _PURPOSES:
        raise ConsentTextError("purpose is not push or network")
    return purpose
