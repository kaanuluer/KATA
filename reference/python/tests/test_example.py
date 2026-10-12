# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib.util
from pathlib import Path


def test_purchase_example_allows_then_denies_then_revokes(capsys):
    path = Path(__file__).resolve().parents[1] / "examples" / "purchase_check.py"
    spec = importlib.util.spec_from_file_location("purchase_check", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    assert module.main() == 0
    output = capsys.readouterr().out
    assert "-> ALLOW" in output
    assert "4200 CAD -> DENY" in output
    assert "MANDATE_REVOKED" in output
