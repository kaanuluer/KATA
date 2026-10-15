# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: Apache-2.0
"""Daily foreign-exchange rates for the unscoped amount ceiling.

The ceiling stays off unless a verifier turns it on. When it is on, amounts
in any currency convert into one reference currency with the rate for that
UTC day. The rate source is supplied by the caller. This module does not
fetch a market.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Mapping, Protocol

from kata_intent.errors import KataError
from kata_intent.values import money


class FxRateSource(Protocol):
    """Reference-currency units received for one unit of ``currency`` on ``day``."""

    def daily_rate(self, currency: str, day: str, reference_currency: str) -> Decimal | None:
        """Return the rate, or ``None`` when that day is unpublished."""


class DailyTableRates:
    """A caller-supplied table of daily rates.

    Keys are ``(currency, reference_currency, YYYY-MM-DD)``. The value is how
    many units of the reference currency equal one unit of ``currency``.
    """

    def __init__(self, table: Mapping[tuple[str, str, str], Decimal | int | str]):
        self._table = {(key[0], key[1], key[2]): money(value) for key, value in table.items()}

    def daily_rate(self, currency: str, day: str, reference_currency: str) -> Decimal | None:
        if currency == reference_currency:
            return Decimal(1)
        rate = self._table.get((currency, reference_currency, day))
        if rate is not None and rate <= 0:
            raise KataError("FX rate must be greater than zero")
        return rate


def convert_amount(amount: Decimal | int, currency: str, day: str, reference_currency: str, source: FxRateSource) -> Decimal | None:
    """Convert ``amount`` into ``reference_currency``. ``None`` means no rate for that day."""

    rate = source.daily_rate(currency, day, reference_currency)
    if rate is None:
        return None
    if rate <= 0:
        raise KataError("FX rate must be greater than zero")
    return money(amount) * rate
