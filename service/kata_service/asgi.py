# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: Apache-2.0
"""FastAPI application. The repository-root ``app.py`` re-exports ``app`` for Vercel."""

from __future__ import annotations

import hmac
import html
import re
import secrets
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response

from kata_service.bureau import BureauError, BureauService, HttpWebhookSender, MemoryRepo, RecordingSender, mailer_from_settings, token_hash
from kata_service.bureau_http import build_router
from kata_service.demo import run_demo
from kata_service.pages import (
    DOCUMENT_SLUGS,
    api_reference,
    dashboard_page,
    documentation_index,
    history_page,
    home_page,
    portal_page,
    render_document,
    schema_bytes,
    schema_index,
    status_page,
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
    if resolved.demo:
        from kata_service.seed import demo_settings

        resolved = demo_settings(resolved)
    app = FastAPI(title="Global Agent Bureau", docs_url="/docs/openapi", redoc_url=None)
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

    @app.get("/simulation")
    def simulation():
        from kata_service.simulation_page import simulation_page

        return HTMLResponse(simulation_page())

    @app.get("/dashboard")
    def dashboard():
        return HTMLResponse(dashboard_page())

    @app.get("/portal")
    def portal():
        return HTMLResponse(portal_page())

    @app.get("/health")
    def health():
        return _health_response(app)

    @app.get("/v1/health")
    def health_v1():
        return _health_response(app)

    @app.get("/status")
    def status():
        _code, body = probe_database(app.state.settings)
        return HTMLResponse(status_page(body))

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

    app.include_router(build_router())
    if resolved.deployment_env == "sandbox":
        from kata_service.amex_http import register_sandbox_routes
        from kata_service.ucp_http import register_sandbox_routes as register_ucp_routes

        register_sandbox_routes(app)
        register_ucp_routes(app)

    @app.post("/mcp")
    async def mcp_post(request: Request):
        from kata_service.mcp_http import handle_mcp

        return await handle_mcp(request, app)

    @app.api_route("/mcp", methods=["GET", "DELETE", "PUT", "PATCH"])
    def mcp_method_not_allowed():
        return JSONResponse(
            {
                "jsonrpc": "2.0",
                "error": {"code": -32601, "message": "Method not found"},
            },
            status_code=405,
            headers={"Allow": "POST"},
        )

    @app.middleware("http")
    async def bureau_guard(request: Request, call_next):
        path = request.url.path
        if path in {"/health", "/v1/health"} or not path.startswith("/v1"):
            return await call_next(request)
        try:
            bureau = ensure_bureau(app)
        except BureauError as exc:
            return _error(exc.status, exc.message)
        header = request.headers.get("authorization", "")
        token = header[7:].strip() if header.startswith("Bearer ") else ""
        subject = token_hash(token) if token else (request.client.host if request.client else "anonymous")
        settings = app.state.settings
        limited = bureau.hit_rate(subject) > settings.rate_limit_per_minute
        endpoint_cap = _endpoint_rate_cap(request.method, path, settings)
        if not limited and endpoint_cap is not None:
            limited = bureau.hit_rate(f"{path}:{subject}") > endpoint_cap
        if limited:
            response = _error(429, "rate limit exceeded", {"Retry-After": "60"})
        else:
            response = await call_next(request)
        try:
            bureau.repo.add_audit(
                {
                    "audit_id": "aud_" + secrets.token_hex(8),
                    "at": bureau.stamp(),
                    "org_id": getattr(request.state, "org_id", None),
                    "key_id": getattr(request.state, "key_id", None),
                    "method": request.method,
                    "path": path,
                    "status": response.status_code,
                    "purpose_code": getattr(request.state, "purpose_code", None),
                    "agent_id": getattr(request.state, "agent_id", None),
                    "environment": "test" if getattr(request.state, "environment", None) == "test" else "live",
                }
            )
        except Exception:
            pass
        return response

    @app.get("/assets/{name}")
    def asset(name: str):
        media = {
            "app.css": "text/css",
            "app.js": "text/javascript",
            "dashboard.js": "text/javascript",
            "portal.js": "text/javascript",
            "gab-logo.svg": "image/svg+xml",
            "gab-logo.png": "image/png",
            "gab-icon.svg": "image/svg+xml",
            "gab-icon-180.png": "image/png",
            "favicon-32.png": "image/png",
            "kata-icon.svg": "image/svg+xml",
            "kata-logo.svg": "image/svg+xml",
            "simulation-results.json": "application/json",
            "chart-final-1-fraud-dollars.png": "image/png",
            "chart-final-2-ring-scores.png": "image/png",
            "chart-final-3-fake-reports.png": "image/png",
            "chart-final-4-loss-by-attacker.png": "image/png",
            "chart-final-5-friction-sybils.png": "image/png",
            "gab-explainer-1080.mp4": "video/mp4",
            "gab-explainer-720.mp4": "video/mp4",
            "gab-explainer-poster.jpg": "image/jpeg",
            "gab-explainer.vtt": "text/vtt",
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

    @app.get("/.well-known/security.txt")
    def security_txt():
        body = (
            "Contact: mailto:info@globalagentbureau.com\n"
            "Expires: 2027-10-15T00:00:00.000Z\n"
            "Preferred-Languages: en\n"
            "Canonical: https://globalagentbureau.com/.well-known/security.txt\n"
        )
        return Response(body, media_type="text/plain; charset=utf-8")

    @app.get("/robots.txt")
    def robots_txt():
        body = (
            "User-agent: *\n"
            "Allow: /\n"
            "\n"
            "# MCP endpoint: /mcp\n"
            "# Documentation: /docs\n"
            "# Status: /status\n"
        )
        return Response(body, media_type="text/plain; charset=utf-8")

    @app.get("/llms.txt")
    def llms_txt():
        body = (
            "# Global Agent Bureau\n"
            "\n"
            "> Agent bureau and technology company. The license is PolyForm Noncommercial 1.0.0.\n"
            "\n"
            "This service checks a signed intent agreement and publishes an agent trust score.\n"
            "\n"
            "## Where to read\n"
            "\n"
            "- [Documentation](/docs): design notes, the API reference, and the JSON schemas\n"
            "- [Status](/status): whether the service and its database check are answering\n"
            "- [MCP](/mcp): remote MCP server. 5 tools over streamable HTTP. Send POST with an API key. GET is not the protocol.\n"
            "- [Sandbox](/docs/sandbox): gab_test_ keys. Live and test rows stay isolated.\n"
            "- [UCP](/docs/ucp-research): sandbox checkout verification. The bureau verifies an action and does not host checkout.\n"
            "- [AmEx intent mapping](/docs/amex-intent-mapping): assumed mapping.\n"
            "\n"
            "## Keys\n"
            "\n"
            "Live keys use the gab_ prefix. Test keys use the gab_test_ prefix and stay in the test partition.\n"
            "\n"
            "## Limits and probes\n"
            "\n"
            "GET /health and GET /v1/health need no API key. The same reading is on /status.\n"
            "A rate limit returns 429 with Retry-After: 60.\n"
            "Malformed input is denied. Responses include security headers.\n"
            "\n"
            "## Latest test round\n"
            "\n"
            "316 checks. SYNTHETIC TEST DATA – not real customers.\n"
        )
        return Response(body, media_type="text/plain; charset=utf-8")

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


def ensure_bureau(app: FastAPI):
    """Build the bureau on first use so importing the app does not open Postgres."""

    existing = getattr(app.state, "bureau", None)
    if existing is not None:
        return existing
    settings = app.state.settings
    store = app.state.store
    if settings.demo or not settings.database_url:
        repo = MemoryRepo()
        if store is None and settings.demo:
            from kata_service.store import MemoryStore

            store = MemoryStore()
            app.state.store = store
        service = BureauService(
            repo,
            log_store=store,
            log_key=settings.log_key(),
            mailer=mailer_from_settings(settings),
            sender=RecordingSender(),
            magic_link_ttl_seconds=settings.magic_link_ttl_seconds,
            session_ttl_seconds=settings.session_ttl_seconds,
            report_daily_cap=settings.report_daily_cap,
            dev_mailbox=settings.dev_mailbox or settings.demo,
            public_base_url=settings.public_base_url,
            policy=settings.score_policy,
            consortium_match_threshold=settings.consortium_match_threshold,
            deployment_env=settings.deployment_env,
        )
        if settings.demo:
            from kata_service.seed import seed_demo

            seed_demo(service)
        app.state.bureau = service
        return service
    from kata_service.bureau_pg import PostgresRepo
    from kata_service.store import open_store

    try:
        repo = PostgresRepo(settings.database_url, settings.schema_url)
        if store is None:
            store = open_store(settings.database_url, settings.schema_url)
            app.state.store = store
    except Exception as exc:
        raise BureauError(503, f"storage is unavailable: {exc}") from exc
    service = BureauService(
        repo,
        log_store=store,
        log_key=settings.log_key(),
        mailer=mailer_from_settings(settings),
        sender=HttpWebhookSender(),
        magic_link_ttl_seconds=settings.magic_link_ttl_seconds,
        session_ttl_seconds=settings.session_ttl_seconds,
        report_daily_cap=settings.report_daily_cap,
        dev_mailbox=settings.dev_mailbox,
        public_base_url=settings.public_base_url,
        policy=settings.score_policy,
        consortium_match_threshold=settings.consortium_match_threshold,
        deployment_env=settings.deployment_env,
    )
    app.state.bureau = service
    return service


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


def _endpoint_rate_cap(method: str, path: str, settings) -> int | None:
    if method != "POST":
        return None
    caps = {
        "/v1/verify": settings.verify_rate_limit_per_minute,
        "/v1/inquiries": settings.inquiry_rate_limit_per_minute,
        "/v1/reports": settings.report_rate_limit_per_minute,
    }
    return caps.get(path)


def probe_database(settings: Settings) -> tuple[int, dict[str, str]]:
    """Ping the database when one is configured. Never include the address or the driver error."""

    if settings.demo or not settings.database_url:
        return 200, {"status": "ok", "database": "memory"}
    try:
        import psycopg

        with psycopg.connect(settings.database_url, connect_timeout=3) as conn:
            row = conn.execute("SELECT 1").fetchone()
        if row is None or row[0] != 1:
            return 503, {"status": "unavailable", "database": "unavailable"}
    except Exception:
        return 503, {"status": "unavailable", "database": "unavailable"}
    return 200, {"status": "ok", "database": "ok"}


def _health_response(app: FastAPI) -> JSONResponse:
    status, body = probe_database(app.state.settings)
    return JSONResponse(body, status_code=status)


def _error(status: int, message: str, headers: dict[str, str] | None = None) -> JSONResponse:
    return JSONResponse({"error": message}, status_code=status, headers=headers)


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
