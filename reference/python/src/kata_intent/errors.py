# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: Apache-2.0
"""Errors for incorrect use of the intent-agreement library."""


class KataError(Exception):
    """The caller used the library incorrectly.

    Evaluating an action does not raise this for a suspicious or out-of-scope
    action. Those cases return a verdict. This exception is for a broken
    lifecycle call: accepting a revoked agreement, a confirmation string that
    does not match the rendering, a malformed key.
    """
