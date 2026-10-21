# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""HTTP routes for the Global Agent Bureau."""

from __future__ import annotations

from decimal import Decimal
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from kata_service.bureau import Auth, BureauError, reject_deep_json, reset_test_mode, use_test_mode


def build_router() -> APIRouter:
    router = APIRouter()

    @router.get("/v1/score-model", summary="Published agent score weights")
    async def score_model(request: Request):
        return await _run(request, lambda auth, body: _bureau(request).score_model(), read_body=False, anonymous=True)

    @router.post("/v1/orgs", summary="Create a participant organization")
    async def create_org(request: Request):
        return await _run(
            request,
            lambda auth, body: _bureau(request).create_org(
                auth,
                str(body.get("name") or ""),
                str(body.get("org_type") or ""),
                None if body.get("entity_kind") is None else str(body.get("entity_kind")),
            ),
        )

    @router.post("/v1/orgs/{org_id}/keys", summary="Issue an API key")
    async def create_key(request: Request, org_id: str):
        def action(auth, body):
            scopes = body.get("scopes")
            if scopes is not None and not isinstance(scopes, list):
                raise BureauError(400, "scopes must be a list")
            return _bureau(request).create_key(
                auth,
                org_id,
                str(body.get("name") or "key"),
                scopes,
                None if body.get("environment") is None else str(body.get("environment")),
            )

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

    @router.post("/v1/agents/{agent_id}/proofing", summary="File identity evidence for an agent")
    async def submit_proofing(request: Request, agent_id: str):
        request.state.agent_id = agent_id
        return await _run(request, lambda auth, body: _bureau(request).submit_proofing(auth, agent_id, body))

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

    @router.get("/v1/webhooks/deliveries", summary="List webhook delivery attempts for this organization")
    async def list_deliveries(request: Request):
        return await _run(request, lambda auth, body: _bureau(request).list_deliveries(auth), read_body=False)

    @router.post("/v1/webhooks/test", summary="Send a signed test alert to one subscription")
    async def test_webhook(request: Request):
        return await _run(
            request,
            lambda auth, body: _bureau(request).test_webhook(auth, str(body.get("subscription_id") or "")),
        )

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
        return await _run(
            request,
            lambda auth, body: _bureau(request).set_status(
                auth, agent_id, "revoked", assertion=_assertion(body), origin=_origin(request)
            ),
        )

    @router.post("/v1/portal/agreements/{agreement_id}/revoke", summary="Principal revokes a stored agreement")
    async def portal_revoke_agreement(request: Request, agreement_id: str):
        return await _run(
            request,
            lambda auth, body: _bureau(request).portal_revoke_agreement(
                auth, agreement_id, assertion=_assertion(body), origin=_origin(request)
            ),
        )

    @router.delete(
        "/v1/portal/subject",
        summary="Remove the signed-in principal from the live database in this process",
    )
    async def remove_portal_subject(request: Request):
        return await _run(
            request,
            lambda auth, body: _bureau(request).remove_portal_subject(
                auth, assertion=_assertion(body), origin=_origin(request)
            ),
        )

    @router.post("/v1/portal/disputes", summary="Dispute an incident")
    async def file_dispute(request: Request):
        def action(auth, body):
            bureau = _bureau(request)
            bureau._screen("dispute", body)
            return bureau.file_dispute(
                auth,
                str(body.get("report_id") or ""),
                str(body.get("statement") or ""),
                assertion=_assertion(body),
                origin=_origin(request),
            )

        return await _run(request, action)

    @router.post("/v1/portal/passkeys/register/options", summary="Start passkey registration")
    async def passkey_register_options(request: Request):
        from kata_service.portal_devices import registration_challenge

        return await _run(
            request,
            lambda auth, body: registration_challenge(_bureau(request), auth, _origin(request)),
            read_body=False,
        )

    @router.post("/v1/portal/passkeys", summary="Store a passkey for this principal")
    async def passkey_register(request: Request):
        from kata_service.portal_devices import register_device

        return await _run(request, lambda auth, body: register_device(_bureau(request), auth, body, _origin(request)))

    @router.post("/v1/portal/passkeys/authenticate/options", summary="Start passkey sign-in")
    async def passkey_auth_options(request: Request):
        from kata_service.portal_devices import authentication_challenge

        return await _run(
            request,
            lambda auth, body: authentication_challenge(_bureau(request), _origin(request)),
            anonymous=True,
            read_body=False,
        )

    @router.post("/v1/portal/passkeys/authenticate", summary="Exchange a passkey assertion for a portal session")
    async def passkey_auth(request: Request):
        from kata_service.portal_devices import authenticate_device

        return await _run(
            request,
            lambda auth, body: authenticate_device(_bureau(request), body.get("credential"), _origin(request)),
            anonymous=True,
        )

    @router.post("/v1/portal/passkeys/assert/options", summary="Start a passkey check for revoke, dispute, or approval")
    async def passkey_assert_options(request: Request):
        from kata_service.portal_devices import assertion_challenge

        return await _run(
            request,
            lambda auth, body: assertion_challenge(_bureau(request), auth, _origin(request)),
            read_body=False,
        )

    @router.get("/v1/portal/devices", summary="List registered devices and what the portal stores")
    async def portal_devices(request: Request):
        from kata_service.portal_devices import list_devices

        return await _run(request, lambda auth, body: list_devices(_bureau(request), auth), read_body=False)

    @router.post("/v1/portal/devices/{credential_id}/remove", summary="Remove a registered passkey")
    async def portal_remove_device(request: Request, credential_id: str):
        from kata_service.portal_devices import remove_device

        return await _run(
            request,
            lambda auth, body: remove_device(_bureau(request), auth, credential_id, _assertion(body), _origin(request)),
        )

    @router.post("/v1/portal/consent", summary="Append a consent event when that flag is on")
    async def portal_consent(request: Request):
        return await _run(request, lambda auth, body: _bureau(request).record_consent(auth, body))

    @router.post("/v1/portal/push", summary="Store a push device after explicit consent")
    async def portal_push(request: Request):
        from kata_service.portal_devices import register_push

        return await _run(request, lambda auth, body: register_push(_bureau(request), auth, body))

    @router.post("/v1/portal/push/{device_id}/remove", summary="Remove a push device")
    async def portal_remove_push(request: Request, device_id: str):
        from kata_service.portal_devices import remove_push

        return await _run(
            request,
            lambda auth, body: remove_push(_bureau(request), auth, device_id, _assertion(body), _origin(request)),
        )

    @router.get("/v1/portal/push/key", summary="Public key for approval notices, when the host has one")
    async def portal_push_key(request: Request):
        from kata_service.portal_devices import push_public_key

        return await _run(request, lambda auth, body: push_public_key(_bureau(request), auth), read_body=False)

    @router.get("/v1/portal/approvals", summary="Approval requests waiting for this individual")
    async def portal_approvals(request: Request):
        from kata_service.portal_devices import list_approvals

        return await _run(request, lambda auth, body: list_approvals(_bureau(request), auth), read_body=False)

    @router.post("/v1/portal/approvals/{approval_id}/approve", summary="Approve one action with a passkey")
    async def portal_approve(request: Request, approval_id: str):
        from kata_service.portal_devices import decide_approval

        return await _run(
            request,
            lambda auth, body: decide_approval(
                _bureau(request), auth, approval_id, "approved", _assertion(body), _origin(request)
            ),
        )

    @router.post("/v1/portal/approvals/{approval_id}/reject", summary="Reject one action with a passkey")
    async def portal_reject(request: Request, approval_id: str):
        from kata_service.portal_devices import decide_approval

        return await _run(
            request,
            lambda auth, body: decide_approval(
                _bureau(request), auth, approval_id, "rejected", _assertion(body), _origin(request)
            ),
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

    @router.post("/v1/admin/consortium/members", summary="Add a consortium member")
    async def add_consortium_member(request: Request):
        return await _run(request, lambda auth, body: _bureau(request).add_consortium_member(auth, str(body.get("org_id") or "")))

    @router.post("/v1/consortium/sightings", summary="Record a fingerprint sighting")
    async def record_sighting(request: Request):
        return await _run(request, lambda auth, body: _bureau(request).record_sighting(auth, str(body.get("fingerprint") or "")))

    @router.post("/v1/consortium/match", summary="Match a fingerprint across members")
    async def match_sightings(request: Request):
        return await _run(request, lambda auth, body: _bureau(request).match_sightings(auth, str(body.get("fingerprint") or "")))

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
            return _error_body(exc)

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
        mode = use_test_mode(bool(getattr(auth, "test", False)))
        try:
            if read_body and request.method != "GET":
                reject_deep_json(body)
            result = action(auth, body)
        finally:
            reset_test_mode(mode)
        return _plain(result)
    except BureauError as exc:
        return _error_body(exc)


def _error_body(exc: BureauError) -> JSONResponse:
    headers = {"Retry-After": "60"} if exc.status == 429 else None
    return JSONResponse({"error": exc.message}, status_code=exc.status, headers=headers)


def _auth(request: Request) -> Auth:
    token = _bearer(request)
    if not token:
        raise BureauError(401, "credentials are required")
    auth = _bureau(request).authenticate(token, admin_token=request.app.state.settings.admin_token)
    request.state.org_id = auth.org_id
    request.state.key_id = auth.key_id
    request.state.environment = "test" if auth.test else "live"
    if auth.principal_id:
        request.state.principal_id = auth.principal_id
    return auth


def _origin(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-host")
    if forwarded:
        host = forwarded.split(",")[0].strip()
        proto = (request.headers.get("x-forwarded-proto") or "https").split(",")[0].strip()
        return f"{proto}://{host}"
    return str(request.base_url).rstrip("/")


def _assertion(body: dict[str, Any]) -> dict[str, Any] | None:
    value = body.get("assertion")
    return value if isinstance(value, dict) else None


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
