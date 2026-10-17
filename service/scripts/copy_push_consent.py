# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Offline copy of push consent timestamps. Not run by the service or by CI.

Dry-run is the default and does not open a database. A write needs --execute,
--approve, a verified backup id, a verified backup timestamp, and the phrase
BACKUP-VERIFIED.
"""

from __future__ import annotations

import sys


def main() -> int:
    from kata_service.copy_push_consent import run

    return run(sys.argv[1:])


if __name__ == "__main__":
    sys.exit(main())
