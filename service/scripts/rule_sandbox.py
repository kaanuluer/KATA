# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Replay a candidate decision rule on synthetic verify requests.

The HTTP route stays unregistered unless GAB_RULE_SANDBOX is on. This script
calls the same pure replay. It does not open a database and it does not read
the process environment. Run it from service/:

    python3 scripts/rule_sandbox.py --seed 20261127 --count 24 --maximum-amount 100
"""

from __future__ import annotations

import sys


def main() -> int:
    from kata_service.rule_sandbox import main as run

    return run(sys.argv[1:])


if __name__ == "__main__":
    sys.exit(main())
