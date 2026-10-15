# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: Apache-2.0
"""Daily FX rates for the unscoped ceiling.

The default source is Frankfurter, which republishes the European Central Bank
reference rates and does not need an API key. A deployment can pass another
``FxFetcher``. The rate is how many units of the reference currency equal one
unit of ``currency``, which is what the reference library's ``DailyTableRates``
stores.
"""

from __future__ import annotations

import json
from decimal import Decimal
from typing import Callable, Protocol
from urllib.request import Request, urlopen

from kata_intent.canonical import encode_decimal
from kata_intent.values import money


class FxFetcher(Protocol):
    def fetch(self, currency: str, day: str, reference_currency: str) -> str | None:
        """Return a decimal string, or ``None`` when that day has no rate."""


class FrankfurterFx:
    """``GET {base}/{day}?from={currency}&to={reference}``."""

    def __init__(self, base_url: str, opener: Callable[[str], str] | None = None):
        self.base_url = base_url.rstrip("/")
        self._opener = opener

    def fetch(self, currency: str, day: str, reference_currency: str) -> str | None:
        if currency == reference_currency:
            return "1"
        url = f"{self.base_url}/{day}?from={currency}&to={reference_currency}"
        raw = self._opener(url) if self._opener is not None else _http_get(url)
        payload = json.loads(raw, parse_float=Decimal)
        rates = payload.get("rates") if isinstance(payload, dict) else None
        if not isinstance(rates, dict) or reference_currency not in rates:
            return None
        return encode_decimal(money(rates[reference_currency]))


def _http_get(url: str) -> str:
    request = Request(
        url,
        headers={
            "User-Agent": "kata-service/0.1 (+https://github.com/kaanuluer/KATA)",
            "Accept": "application/json",
        },
    )
    with urlopen(request, timeout=10) as response:  # noqa: S310 — the host is the configured FX source
        return response.read().decode("utf-8")
