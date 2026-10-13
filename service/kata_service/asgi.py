# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: Apache-2.0
"""FastAPI application. The repository-root ``app.py`` re-exports ``app`` for Vercel."""

from __future__ import annotations

import hmac
import html
import re
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response

from kata_service.demo import run_demo
from kata_service.pages import (
    DOCUMENT_SLUGS,
    api_reference,
    documentation_index,
    history_page,
    home_page,
    render_document,
    schema_bytes,
    schema_index,
)

from kata_intent.canonical import canonical_bytes
from kata_intent.errors import KataError
from kata_intent.keys import public_key_from_jwk
from kata_intent.revocation import TransparencyLog, verify_revocation_push
from kata_intent.values import prefixed_hash

from kata_service.fx import FrankfurterFx, FxFetcher
from kata_service.settings import REVOCATION_MAX_AGE_SECONDS, Settings, settings_from_env
from kata_service.store import Store, open_store, utcnow

_DAY = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_CURRENCY = re.compile(r"^[A-Z]{3}$")


def create_app(
    settings: Settings | None = None,
    store: Store | None = None,
    fx_fetcher: FxFetcher | None = None,
) -> FastAPI:
    """Build the service. Tests pass a memory store. Vercel uses ``app`` below."""

    resolved = settings if settings is not None else settings_from_env()
    app = FastAPI(title="KATA deployment service", docs_url="/docs/openapi", redoc_url=None)
    app.state.settings = resolved
    app.state.store = store
    app.state.fx = fx_fetcher if fx_fetcher is not None else FrankfurterFx(resolved.fx_source_url)

    pages = _static_dir()

    @app.get("/")
    def home():
        return HTMLResponse(home_page())

    @app.get("/history")
    def history():
        return HTMLResponse(history_page())

    @app.get("/docs")
    def docs():
        return _page(documentation_index)

    @app.get("/docs/api")
    def docs_api():
        return _page(api_reference)

    @app.get("/docs/schemas")
    def docs_schemas():
        return _page(schema_index)

    @app.get("/docs/schemas/{name}.json")
    def docs_schema_file(name: str):
        try:
            payload = schema_bytes(f"{name}.json")
        except FileNotFoundError as exc:
            return _error(500, str(exc))
        if payload is None:
            return _error(404, "schema was not found")
        return Response(payload, media_type="application/json")

    def _bind_document(slug: str) -> Callable[[], HTMLResponse | JSONResponse]:
        def handler():
            try:
                page = render_document(slug)
            except FileNotFoundError as exc:
                return _missing_docs(exc)
            if page is None:
                return _error(404, "document was not found")
            return HTMLResponse(page)

        handler.__name__ = "docs_" + slug.replace("-", "_")
        return handler

    for _slug in DOCUMENT_SLUGS:
        app.add_api_route(
            f"/docs/{_slug}",
            _bind_document(_slug),
            methods=["GET"],
            response_model=None,
        )

    @app.get("/assets/{name}")
    def asset(name: str):
        media = {
            "app.css": "text/css",
            "app.js": "text/javascript",
            "kata-icon.svg": "image/svg+xml",
            "kata-logo.svg": "image/svg+xml",
        }.get(name)
        if media is None:
            return _error(404, "asset was not found")
        return FileResponse(pages / name, media_type=media)

    @app.post("/demo/check")
    async def demo_check(request: Request):
        try:
            payload = await request.json()
        except Exception:  # noqa: BLE001
            return _error(400, "demo body must be JSON")
        try:
            return run_demo(payload)
        except ValueError as exc:
            return _error(400, str(exc))

    @app.get("/v1/revocations")
    def revocation_list():
        store_or_error = _require_store(app)
        if isinstance(store_or_error, JSONResponse):
            return store_or_error
        body = {"revocations": store_or_error.list_revocations()}
        return JSONResponse(
            body,
            headers={"Cache-Control": f"public, max-age={REVOCATION_MAX_AGE_SECONDS}"},
        )

    @app.post("/v1/revocations/push")
    async def revocation_push(request: Request):
        blocked = _configured(app)
        if blocked is not None:
            return blocked
        held = _require_store(app)
        if isinstance(held, JSONResponse):
            return held
        settings_now = app.state.settings
        if settings_now.push_notifier_jwk is None:
            return _error(503, "KATA_PUSH_NOTIFIER_JWK is not set")
        if settings_now.log_key() is None:
            return _error(503, "KATA_LOG_SIGNING_SEED is not set")
        try:
            notice = await request.json()
        except Exception:  # noqa: BLE001 — a bad body is a 400, not a stack trace
            return _error(400, "push body must be JSON")
        if not isinstance(notice, dict):
            return _error(400, "push body must be a JSON object")
        try:
            notifier = public_key_from_jwk(settings_now.push_notifier_jwk)
        except KataError as exc:
            return _error(500, str(exc))
        inner = verify_revocation_push(notice, notifier)
        if inner is None:
            return _error(401, "revocation push did not verify")
        revocation_id = prefixed_hash(canonical_bytes(inner))
        try:
            record = held.record_revocation(revocation_id, inner, settings_now.log_key(), utcnow())
        except KataError as exc:
            return _error(400, str(exc))
        if record is None:
            return {"stored": False, "revocation_id": revocation_id}
        return {"stored": True, "revocation_id": revocation_id, "sequence": record["sequence"]}

    @app.post("/v1/log/entries")
    async def append_entry(request: Request):
        blocked = _configured(app)
        if blocked is not None:
            return blocked
        settings_now = app.state.settings
        if not settings_now.append_token:
            return _error(503, "KATA_APPEND_TOKEN is not set")
        if not _bearer_matches(request, settings_now.append_token):
            return _error(401, "append token does not match")
        if settings_now.log_key() is None:
            return _error(503, "KATA_LOG_SIGNING_SEED is not set")
        held = _require_store(app)
        if isinstance(held, JSONResponse):
            return held
        try:
            payload = await request.json()
        except Exception:  # noqa: BLE001
            return _error(400, "log body must be JSON")
        if not isinstance(payload, dict) or not isinstance(payload.get("body"), dict):
            return _error(400, "log append needs kind and a body object")
        try:
            record, head = held.append_and_sign(
                str(payload.get("kind")), payload["body"], settings_now.log_key(), utcnow()
            )
        except KataError as exc:
            return _error(400, str(exc))
        return {"entry": record, "tree_head": head}

    @app.get("/v1/log/entries/{sequence}")
    def get_entry(sequence: int):
        held = _require_store(app)
        if isinstance(held, JSONResponse):
            return held
        entry = held.get_entry(sequence)
        if entry is None:
            return _error(404, "log entry was not found")
        return {"entry": entry}

    @app.get("/v1/log/entries/{sequence}/proof")
    def inclusion_proof(sequence: int):
        held = _require_store(app)
        if isinstance(held, JSONResponse):
            return held
        entries, _head = held.snapshot()
        log = TransparencyLog()
        log.entries = list(entries)
        try:
            proof = log.inclusion_proof(sequence)
        except KataError as exc:
            return _error(404, str(exc))
        entry = entries[sequence - 1]
        return {
            "sequence": sequence,
            "index": sequence - 1,
            "leaf": entry["entry_hash"],
            "proof": proof,
            "root": log.root(),
            "tree_size": len(entries),
        }

    @app.get("/v1/log/head")
    def tree_head():
        held = _require_store(app)
        if isinstance(held, JSONResponse):
            return held
        _entries, head = held.snapshot()
        if head is None:
            return _error(404, "the transparency log has no signed tree head")
        return head

    @app.get("/.well-known/kata-keys.json")
    def well_known():
        blocked = _configured(app)
        if blocked is not None:
            return blocked
        keys: list[dict[str, Any]] = []
        log_key = app.state.settings.log_key()
        if log_key is not None:
            keys.append({"public_key": log_key.public.to_jwk()})
        for record in app.state.settings.published_keys:
            keys.append(dict(record))
        return {"keys": keys}

    @app.get("/v1/fx")
    def fx_rate(currency: str, day: str | None = None, reference: str | None = None, reference_currency: str | None = None):
        target = reference_currency or reference or "USD"
        if not _CURRENCY.match(currency) or not _CURRENCY.match(target):
            return _error(400, "currency codes are three letters")
        chosen_day = day or datetime.now(timezone.utc).date().isoformat()
        if not _DAY.match(chosen_day):
            return _error(400, "day is YYYY-MM-DD")
        if currency == target:
            return {"currency": currency, "reference_currency": target, "day": chosen_day, "rate": "1"}
        held = _require_store(app)
        if isinstance(held, JSONResponse):
            return held
        cached = held.get_fx(currency, target, chosen_day)
        if cached is not None:
            return _fx_body(currency, target, chosen_day, cached)
        try:
            rate = app.state.fx.fetch(currency, chosen_day, target)
        except Exception:  # noqa: BLE001 — the upstream feed is outside this process
            return _error(502, "FX source did not answer")
        if rate is None:
            return _error(404, f"no {target} rate for {currency} on {chosen_day}")
        held.put_fx(currency, target, chosen_day, rate)
        return _fx_body(currency, target, chosen_day, rate)

    return app


def _fx_body(currency: str, reference_currency: str, day: str, rate: str) -> dict[str, str]:
    return {
        "currency": currency,
        "reference_currency": reference_currency,
        "day": day,
        "rate": rate,
    }


def _require_store(app: FastAPI) -> Store | JSONResponse:
    if app.state.store is not None:
        return app.state.store
    settings = app.state.settings
    if not settings.database_url:
        return _error(503, "DATABASE_URL is not set")
    try:
        app.state.store = open_store(settings.database_url, settings.schema_url)
    except Exception as exc:  # noqa: BLE001 — connection failures stay on this response
        return _error(503, f"storage is unavailable: {exc}")
    return app.state.store


def _configured(app: FastAPI) -> JSONResponse | None:
    if app.state.settings.config_error:
        return _error(500, app.state.settings.config_error)
    return None


def _bearer_matches(request: Request, expected: str) -> bool:
    header = request.headers.get("authorization", "")
    prefix = "Bearer "
    if not header.startswith(prefix):
        return False
    return hmac.compare_digest(header[len(prefix) :], expected)


def _static_dir():
    from pathlib import Path

    return Path(__file__).resolve().parent / "static"


def _error(status: int, message: str) -> JSONResponse:
    return JSONResponse({"error": message}, status_code=status)


def _missing_docs(exc: FileNotFoundError) -> HTMLResponse:
    message = html.escape(str(exc))
    return HTMLResponse(f"<p>{message}</p>", status_code=500)


def _page(builder: Callable[[], str]) -> HTMLResponse:
    try:
        body = builder()
    except FileNotFoundError as exc:
        return _missing_docs(exc)
    return HTMLResponse(body)


app = create_app()
