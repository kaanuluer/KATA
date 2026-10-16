# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""The installed wheel has to carry the bureau migration. Vercel installs the package and does not keep the source tree."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def test_installed_package_can_read_the_bureau_migration(tmp_path: Path):
    service = Path(__file__).resolve().parents[1]
    target = tmp_path / "install"
    target.mkdir()
    subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--target",
            str(target),
            "--no-deps",
            "--upgrade",
            str(service),
        ],
        check=True,
        cwd=tmp_path,
    )
    probe = tmp_path / "read_migration.py"
    probe.write_text(
        "import kata_service.bureau_pg as migration\n"
        "text = migration.migration_sql()\n"
        "assert 'CREATE TABLE IF NOT EXISTS gab_organizations' in text\n"
        "assert 'CREATE TABLE IF NOT EXISTS gab_org_signals' in text\n"
        "assert migration._MIGRATION.is_file()\n"
        "names = sorted(path.name for path in migration._MIGRATIONS.glob('*.sql'))\n"
        "assert names == ['001_bureau.sql', '002_defenses.sql', '003_proofing.sql', '004_consortium.sql', '005_org_signals.sql', '006_webhook.sql']\n",
        encoding="utf-8",
    )
    env = os.environ.copy()
    env["PYTHONPATH"] = str(target)
    subprocess.run([sys.executable, str(probe)], check=True, cwd=tmp_path, env=env)
