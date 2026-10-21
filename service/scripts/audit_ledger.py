# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Read-only ledger audit. Not run by the service or by CI.

Dry-run is the default and does not open a database.
"""

from __future__ import annotations

import sys


def main() -> int:
    from kata_service.audit_ledger import run

    return run(sys.argv[1:])


if __name__ == "__main__":
    sys.exit(main())
