# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Sandbox routes for the AmEx intent mapping prototype.

Registered only when GAB_ENV=sandbox. A gab_test_ key is required.
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from kata_service.amex_adapter import AdapterError, convert_to_amex, convert_to_kata
from kata_service.bureau import BureauError, reset_test_mode, use_test_mode
from kata_service.bureau_http import _bearer, _json_body


def register_sandbox_routes(app: FastAPI) -> None:
    """Attach the prototype routes. Production does not register them."""

    @app.post("/v1/sandbox/amex-intent/to-kata", summary="Map an AmEx-style intent record in the sandbox")
    async def amex_to_kata(request: Request):
        return await _convert(request, "to_kata")

    @app.post("/v1/sandbox/amex-intent/to-amex", summary="Map a partial KATA agreement back in the sandbox")
    async def amex_to_amex(request: Request):
        return await _convert(request, "to_amex")


async def _convert(request: Request, direction: str) -> JSONResponse | dict[str, Any]:
    try:
        _guard(request)
        body = await _json_body(request)
        mode = use_test_mode(True)
        try:
            if direction == "to_kata":
                result = convert_to_kata(body)
            else:
                result = convert_to_amex(body)
        finally:
            reset_test_mode(mode)
    except BureauError as exc:
        return JSONResponse({"error": exc.message}, status_code=exc.status)
    except AdapterError as exc:
        return JSONResponse({"error": exc.message}, status_code=400)
    return result


def _guard(request: Request) -> None:
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
