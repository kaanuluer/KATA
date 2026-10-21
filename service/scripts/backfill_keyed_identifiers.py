# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Offline backfill for keyed email identifiers. Not run by the service or by CI.

Dry-run is the default and does not open a database. A write needs --execute,
--approve, a verified backup id, a verified backup timestamp, and the phrase
BACKUP-VERIFIED. See kata_service.backfill_identifiers for the rollback note.

Do not commit a database URL or key material. Build the key provider in the
process environment (GAB_KEY_PROVIDER) and pass nothing secret on the command line.
"""

from __future__ import annotations

import os
import sys


def main() -> int:
    from kata_service.backfill_identifiers import run
    from kata_service.keys import provider_from_env

    if "--execute" not in sys.argv[1:]:
        return run(sys.argv[1:])
    provider = provider_from_env(dict(os.environ), deployment_env=os.environ.get("GAB_ENV", "production"))
    return run(sys.argv[1:], provider=provider)


if __name__ == "__main__":
    sys.exit(main())
