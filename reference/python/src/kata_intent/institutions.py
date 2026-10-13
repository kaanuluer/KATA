# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: Apache-2.0
"""Institution signing keys.

A merchant, payment provider, or issuer publishes keys at
``https://<domain>/.well-known/kata-keys.json``. KATA also keeps an allowlist.
A rotated key remains acceptable until the grace period after ``not_after``
ends. The default grace is seven days. This module does not open a network
connection; the caller supplies the document the domain would return.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Callable, Mapping

from kata_intent.errors import KataError
from kata_intent.keys import PublicKey, public_key_from_jwk
from kata_intent.values import parse_time

DEFAULT_GRACE_SECONDS = 7 * 24 * 3600
WELL_KNOWN_PATH = "/.well-known/kata-keys.json"


def well_known_url(domain: str) -> str:
    """The URL where ``domain`` publishes its KATA keys."""

    host = domain.strip().removeprefix("https://").removeprefix("http://").split("/")[0].strip()
    return f"https://{host}{WELL_KNOWN_PATH}"


class InstitutionDirectory:
    """Allowlist plus a ``.well-known`` fetcher.

    ``allowlist`` maps an institution id to a list of key records
    ``{"public_key": jwk or PublicKey, "not_before": optional, "not_after": optional, "domain": optional}``.
    ``well_known`` is ``domain -> document``. The document has ``keys`` in the same shape.
    """

    def __init__(
        self,
        allowlist: Mapping[str, list[Mapping[str, Any]]] | None = None,
        well_known: Callable[[str], Mapping[str, Any]] | None = None,
        grace_seconds: int = DEFAULT_GRACE_SECONDS,
    ):
        if grace_seconds < 0:
            raise KataError("institution key grace cannot be negative")
        self.allowlist = dict(allowlist or {})
        self.well_known = well_known
        self.grace = timedelta(seconds=grace_seconds)

    def trusts(self, institution_id: str, public_key: PublicKey, now: datetime, domain: str | None = None) -> bool:
        """True when ``public_key`` is on the allowlist or in the domain document, including grace."""

        records = list(self.allowlist.get(institution_id) or [])
        if domain is None:
            for record in records:
                if isinstance(record.get("domain"), str):
                    domain = record["domain"]
                    break
        if domain and self.well_known is not None:
            try:
                document = self.well_known(domain)
            except KataError:
                document = None
            if isinstance(document, Mapping):
                published = document.get("keys") or []
                if isinstance(published, list):
                    records.extend(published)
        for record in records:
            key = _record_key(record)
            if key is None or key.fingerprint != public_key.fingerprint or key.algorithm != public_key.algorithm:
                continue
            if _within_window(record, now, self.grace):
                return True
        return False


def _record_key(record: Mapping[str, Any]) -> PublicKey | None:
    material = record.get("public_key")
    if isinstance(material, PublicKey):
        return material
    if isinstance(material, Mapping):
        try:
            return public_key_from_jwk(dict(material))
        except KataError:
            return None
    return None


def _within_window(record: Mapping[str, Any], now: datetime, grace: timedelta) -> bool:
    not_before = record.get("not_before")
    not_after = record.get("not_after")
    if not_before and now < parse_time(str(not_before)):
        return False
    if not_after and now > parse_time(str(not_after)) + grace:
        return False
    return True
