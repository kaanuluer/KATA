# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Sandbox route that checks a UCP checkout.

Registered only when GAB_ENV=sandbox. A gab_test_ key is required.
The bureau does not host checkout.
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from kata_service.bureau import BureauError, reject_deep_json, reset_test_mode, use_test_mode
from kata_service.bureau_http import _bearer, _json_body, _plain


def register_sandbox_routes(app: FastAPI) -> None:
    """Attach the checkout check. Production does not register it."""

    @app.post("/v1/sandbox/ucp/verify-checkout", summary="Check a UCP checkout in the sandbox")
    async def verify_checkout(request: Request):
        return await _handle(request)


async def _handle(request: Request) -> JSONResponse | dict[str, Any]:
    try:
        from kata_service.asgi import ensure_bureau

        token = _bearer(request)
        if not token:
            raise BureauError(401, "credentials are required")
        bureau = ensure_bureau(request.app)
        auth = bureau.authenticate(token, admin_token=request.app.state.settings.admin_token)
        if auth.kind != "key" or not token.startswith("gab_test_"):
            raise BureauError(403, "this route accepts test keys")
        request.state.org_id = auth.org_id
        request.state.key_id = auth.key_id
        request.state.environment = "test"
        body = await _json_body(request)
        reject_deep_json(body)
        mode = use_test_mode(True)
        try:
            result = bureau.verify_checkout(auth, body)
        finally:
            reset_test_mode(mode)
    except BureauError as exc:
        return JSONResponse({"error": exc.message}, status_code=exc.status)
    return _plain(result)
