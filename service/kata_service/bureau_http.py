# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""HTTP routes for the Global Agent Bureau."""

from __future__ import annotations

from decimal import Decimal
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from kata_service.bureau import Auth, BureauError


def build_router() -> APIRouter:
    router = APIRouter()

    @router.post("/v1/orgs", summary="Create a participant organization")
    async def create_org(request: Request):
        return await _run(request, lambda auth, body: _bureau(request).create_org(auth, str(body.get("name") or ""), str(body.get("org_type") or "")))

    @router.post("/v1/orgs/{org_id}/keys", summary="Issue an API key")
    async def create_key(request: Request, org_id: str):
        def action(auth, body):
            scopes = body.get("scopes")
            if scopes is not None and not isinstance(scopes, list):
                raise BureauError(400, "scopes must be a list")
            return _bureau(request).create_key(auth, org_id, str(body.get("name") or "key"), scopes)

        return await _run(request, action)

    @router.get("/v1/orgs/{org_id}/keys", summary="List API key prefixes")
    async def list_keys(request: Request, org_id: str):
        return await _run(request, lambda auth, body: _bureau(request).list_keys(auth, org_id), read_body=False)

    @router.post("/v1/keys/{key_id}/rotate", summary="Rotate an API key")
    async def rotate_key(request: Request, key_id: str):
        return await _run(request, lambda auth, body: _bureau(request).rotate_key(auth, key_id), read_body=False)

    @router.post("/v1/orgs/{org_id}/emails", summary="Register an organization login email")
    async def org_email(request: Request, org_id: str):
        return await _run(request, lambda auth, body: _bureau(request).register_org_email(auth, org_id, str(body.get("email") or "")))

    @router.post("/v1/agents", summary="Register an agent")
    async def register_agent(request: Request):
        return await _run(request, lambda auth, body: _mark_agent(request, _bureau(request).register_agent(auth, body)))

    @router.get("/v1/agents/{agent_id}", summary="Look up an agent")
    async def get_agent(request: Request, agent_id: str):
        request.state.agent_id = agent_id
        return await _run(request, lambda auth, body: _bureau(request).get_agent(auth, agent_id), read_body=False)

    @router.get("/v1/agents", summary="Look up an agent by key fingerprint")
    async def lookup_agent(request: Request, fingerprint: str):
        return await _run(request, lambda auth, body: _bureau(request).lookup_fingerprint(auth, fingerprint), read_body=False)

    @router.post("/v1/agents/{agent_id}/attest", summary="Attest an agent")
    async def attest_agent(request: Request, agent_id: str):
        request.state.agent_id = agent_id
        return await _run(request, lambda auth, body: _bureau(request).attest_agent(auth, agent_id), read_body=False)

    @router.post("/v1/agents/{agent_id}/status", summary="Change agent status")
    async def agent_status(request: Request, agent_id: str):
        request.state.agent_id = agent_id
        return await _run(request, lambda auth, body: _bureau(request).set_status(auth, agent_id, str(body.get("status") or "")))

    @router.post("/v1/agents/{agent_id}/intents", summary="Store a signed intent agreement")
    async def store_intent(request: Request, agent_id: str):
        request.state.agent_id = agent_id
        return await _run(request, lambda auth, body: _bureau(request).store_intent(auth, agent_id, body))

    @router.get("/v1/agents/{agent_id}/intents", summary="List stored intent agreements")
    async def list_intents(request: Request, agent_id: str):
        request.state.agent_id = agent_id
        return await _run(request, lambda auth, body: _bureau(request).list_intents(auth, agent_id), read_body=False)

    @router.post("/v1/verify", summary="Verify a payment request against stored intents")
    async def verify(request: Request):
        def action(auth, body):
            request.state.agent_id = body.get("agent_id")
            return _bureau(request).verify(auth, body)

        return await _run(request, action)

    @router.post("/v1/reports", summary="Report an outcome or incident")
    async def report(request: Request):
        def action(auth, body):
            request.state.agent_id = body.get("agent_id")
            return _bureau(request).report(auth, body)

        return await _run(request, action)

    @router.get("/v1/agents/{agent_id}/reports", summary="Read incident reports")
    async def list_reports(request: Request, agent_id: str):
        request.state.agent_id = agent_id
        return await _run(request, lambda auth, body: _bureau(request).list_reports(auth, agent_id), read_body=False)

    @router.post("/v1/inquiries", summary="Inquire about an agent")
    async def inquire(request: Request):
        def action(auth, body):
            request.state.agent_id = body.get("agent_id")
            request.state.purpose_code = body.get("purpose_code")
            return _bureau(request).inquire(auth, body)

        return await _run(request, action)

    @router.post("/v1/subscriptions", summary="Subscribe to agent alerts")
    async def subscribe(request: Request):
        def action(auth, body):
            request.state.agent_id = body.get("agent_id")
            return _bureau(request).subscribe(auth, str(body.get("agent_id") or ""), str(body.get("webhook_url") or ""))

        return await _run(request, action)

    @router.get("/v1/subscriptions", summary="List alert subscriptions")
    async def list_subscriptions(request: Request):
        return await _run(request, lambda auth, body: _bureau(request).list_subscriptions(auth), read_body=False)

    @router.delete("/v1/subscriptions/{subscription_id}", summary="Remove an alert subscription")
    async def unsubscribe(request: Request, subscription_id: str):
        return await _run(request, lambda auth, body: _bureau(request).unsubscribe(auth, subscription_id), read_body=False)

    @router.get("/v1/alerts", summary="List alerts delivered to this organization")
    async def list_alerts(request: Request):
        return await _run(request, lambda auth, body: _bureau(request).list_alerts(auth), read_body=False)

    @router.get("/v1/audit", summary="Read the audit log for this organization")
    async def list_audit(request: Request):
        return await _run(request, lambda auth, body: _bureau(request).list_audit(auth), read_body=False)

    @router.post("/v1/portal/magic-link", summary="Email a portal sign-in link")
    async def portal_link(request: Request):
        return await _run(request, lambda auth, body: _bureau(request).request_portal_link(str(body.get("email") or "")), anonymous=True)

    @router.post("/v1/dashboard/magic-link", summary="Email an organization sign-in link")
    async def dashboard_link(request: Request):
        return await _run(request, lambda auth, body: _bureau(request).request_org_link(str(body.get("email") or "")), anonymous=True)

    @router.post("/v1/sessions", summary="Exchange a magic link for a session")
    async def session(request: Request):
        return await _run(request, lambda auth, body: _bureau(request).consume_link(str(body.get("token") or "")), anonymous=True)

    @router.get("/v1/portal/agents", summary="List the principal's agents")
    async def portal_agents(request: Request):
        return await _run(request, lambda auth, body: _bureau(request).portal_agents(auth), read_body=False)

    @router.get("/v1/portal/agents/{agent_id}/authorizations", summary="List authorizations for one agent")
    async def portal_authorizations(request: Request, agent_id: str):
        request.state.agent_id = agent_id
        return await _run(request, lambda auth, body: _bureau(request).portal_authorizations(auth, agent_id), read_body=False)

    @router.get("/v1/portal/agents/{agent_id}/reports", summary="List incidents filed about the principal's agent")
    async def portal_reports(request: Request, agent_id: str):
        request.state.agent_id = agent_id
        return await _run(request, lambda auth, body: _bureau(request).portal_reports(auth, agent_id), read_body=False)

    @router.get("/v1/portal/inquiries", summary="List inquiries about the principal's agents")
    async def portal_inquiries(request: Request):
        return await _run(request, lambda auth, body: _bureau(request).portal_inquiries(auth), read_body=False)

    @router.post("/v1/portal/agents/{agent_id}/revoke", summary="Principal revokes an agent")
    async def portal_revoke_agent(request: Request, agent_id: str):
        request.state.agent_id = agent_id
        return await _run(request, lambda auth, body: _bureau(request).set_status(auth, agent_id, "revoked"), read_body=False)

    @router.post("/v1/portal/agreements/{agreement_id}/revoke", summary="Principal revokes a stored agreement")
    async def portal_revoke_agreement(request: Request, agreement_id: str):
        return await _run(request, lambda auth, body: _bureau(request).portal_revoke_agreement(auth, agreement_id), read_body=False)

    @router.post("/v1/portal/disputes", summary="Dispute an incident")
    async def file_dispute(request: Request):
        return await _run(
            request,
            lambda auth, body: _bureau(request).file_dispute(auth, str(body.get("report_id") or ""), str(body.get("statement") or "")),
        )

    @router.get("/v1/portal/disputes", summary="List the principal's disputes")
    async def portal_disputes(request: Request):
        return await _run(request, lambda auth, body: _bureau(request).portal_disputes(auth), read_body=False)

    @router.post("/v1/admin/seed-demo", summary="Insert the public demo rows when the host allows it")
    async def seed_demo_route(request: Request):
        def action(auth, body):
            if not auth.admin:
                raise BureauError(403, "admin credentials are required")
            if not request.app.state.settings.allow_demo_seed:
                raise BureauError(403, "demo seed is disabled")
            from kata_service.seed import seed_demo

            seeded = seed_demo(_bureau(request))
            seeded.pop("admin_token", None)
            return seeded

        return await _run(request, action, read_body=False)

    @router.get("/v1/admin/disputes", summary="Admin dispute queue")
    async def admin_disputes(request: Request):
        return await _run(request, lambda auth, body: _bureau(request).admin_disputes(auth), read_body=False)

    @router.post("/v1/admin/disputes/{dispute_id}", summary="Review a dispute")
    async def review_dispute(request: Request, dispute_id: str):
        return await _run(
            request,
            lambda auth, body: _bureau(request).review_dispute(auth, dispute_id, str(body.get("status") or ""), body.get("outcome")),
        )

    @router.get("/v1/dev/mailbox", summary="Latest development magic link")
    async def dev_mailbox(request: Request):
        try:
            return _plain(_bureau(request).latest_dev_link())
        except BureauError as exc:
            return JSONResponse({"error": exc.message}, status_code=exc.status)

    return router


def _bureau(request: Request):
    return request.app.state.bureau


async def _run(request: Request, action, *, read_body: bool = True, anonymous: bool = False):
    try:
        body: dict[str, Any] = {}
        if read_body and request.method != "GET":
            body = await _json_body(request)
        auth = Auth()
        if not anonymous:
            auth = _auth(request)
        elif _bearer(request):
            try:
                auth = _auth(request)
            except BureauError:
                auth = Auth()
        result = action(auth, body)
        return _plain(result)
    except BureauError as exc:
        return JSONResponse({"error": exc.message}, status_code=exc.status)


def _auth(request: Request) -> Auth:
    token = _bearer(request)
    if not token:
        raise BureauError(401, "credentials are required")
    auth = _bureau(request).authenticate(token, admin_token=request.app.state.settings.admin_token)
    request.state.org_id = auth.org_id
    request.state.key_id = auth.key_id
    if auth.principal_id:
        request.state.principal_id = auth.principal_id
    return auth


def _bearer(request: Request) -> str:
    header = request.headers.get("authorization", "")
    prefix = "Bearer "
    if not header.startswith(prefix):
        return ""
    return header[len(prefix) :].strip()


async def _json_body(request: Request) -> dict[str, Any]:
    try:
        payload = await request.json()
    except Exception as exc:
        raise BureauError(400, "body must be JSON") from exc
    if not isinstance(payload, dict):
        raise BureauError(400, "body must be a JSON object")
    return payload


def _mark_agent(request: Request, view: dict[str, Any]) -> dict[str, Any]:
    request.state.agent_id = view.get("agent_id")
    return view


def _plain(value: Any) -> Any:
    if isinstance(value, Decimal):
        return int(value) if value == value.to_integral_value() else str(value)
    if isinstance(value, dict):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    return value
