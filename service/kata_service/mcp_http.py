# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Remote MCP endpoint. Protocol revision 2026-07-28, streamable HTTP.

The official pages checked on 16 October 2026 are listed in docs/mcp.md.
This module does not invent a second score partition. Tool work runs inside
use_test_mode, which is the sandbox switch already on this branch.
"""

from __future__ import annotations

import base64
import json
import secrets
from typing import Any
from urllib.parse import urlparse

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

from kata_service.asgi import _endpoint_rate_cap, ensure_bureau
from kata_service.bureau import BureauError, reset_test_mode, token_hash, use_test_mode
from kata_service.bureau_http import _plain

PROTOCOL_VERSION = "2026-07-28"
_META_VERSION = "io.modelcontextprotocol/protocolVersion"
_SERVER_INFO = {
    "io.modelcontextprotocol/serverInfo": {
        "name": "global-agent-bureau",
        "version": "1",
    }
}
_HIDDEN_KEYS = {"token", "secret", "secret_hash", "password", "authorization"}

_ACTION = {
    "type": "object",
    "description": "The action to check. Same object the HTTP verify route accepts.",
    "additionalProperties": True,
}
_OUTPUT = {"type": "object", "additionalProperties": True}

TOOLS: tuple[dict[str, Any], ...] = (
    {
        "name": "verify_agent",
        "title": "Verify an agent action",
        "description": (
            "Check one proposed action against the agent's stored intent agreement. "
            "The result is ALLOW, DENY, or STEP_UP. A gab_test_ key uses the test "
            "partition only, so a test result does not change a production score."
        ),
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "agent_id": {"type": "string", "description": "Registered agent id."},
                "action": _ACTION,
                "agreement_id": {
                    "type": "string",
                    "description": "Stored agreement to check. Required when more than one is active.",
                },
                "intent_id": {"type": "string", "description": "Intent id inside the agreement, when the action names one."},
            },
            "required": ["agent_id", "action"],
        },
        "outputSchema": _OUTPUT,
    },
    {
        "name": "inquire",
        "title": "Inquire about an agent",
        "description": (
            "Read one agent's status, active authorizations, revocation notes, "
            "incident counts, and trust score for a stated purpose. An inquiry "
            "does not change the score. A gab_test_ key reads the test partition only."
        ),
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "agent_id": {"type": "string", "description": "Registered agent id."},
                "purpose_code": {
                    "type": "string",
                    "description": "Why this read is happening.",
                    "enum": [
                        "payment_authorization",
                        "account_opening",
                        "fraud_investigation",
                        "dispute_resolution",
                        "ongoing_monitoring",
                        "agent_onboarding",
                    ],
                },
            },
            "required": ["agent_id", "purpose_code"],
        },
        "outputSchema": _OUTPUT,
    },
    {
        "name": "report",
        "title": "Report an agent outcome",
        "description": (
            "File a transaction outcome, fraud incident, chargeback, or policy "
            "violation for an agent. The filing changes the score in that key's "
            "partition. A gab_test_ key does not change a production score. "
            "evidence_hash is sha256: followed by 64 hex characters."
        ),
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "agent_id": {"type": "string", "description": "Registered agent id."},
                "kind": {
                    "type": "string",
                    "enum": ["transaction_outcome", "fraud_incident", "chargeback", "policy_violation"],
                },
                "evidence_hash": {
                    "type": "string",
                    "description": "sha256: and 64 hex characters.",
                    "pattern": "^sha256:[0-9a-f]{64}$",
                },
                "summary": {"type": "string", "description": "Short note, at most 500 characters."},
                "outcome": {
                    "type": "string",
                    "enum": ["settled", "loss", "cleared"],
                    "description": "Optional settlement outcome.",
                },
                "action_id": {"type": "string", "description": "Optional id of an action already checked."},
            },
            "required": ["agent_id", "kind", "evidence_hash", "summary"],
        },
        "outputSchema": _OUTPUT,
    },
    {
        "name": "check_revocation",
        "title": "Check revocation",
        "description": (
            "Read the public revocation list from the transparency log. "
            "Pass agent_id to also read that agent's status in this key's partition."
        ),
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "agent_id": {"type": "string", "description": "Optional agent id in this key's partition."},
            },
        },
        "outputSchema": {
            "type": "object",
            "additionalProperties": True,
            "properties": {"revocations": {"type": "array"}},
            "required": ["revocations"],
        },
    },
    {
        "name": "fetch_signed_receipt",
        "title": "Fetch a signed log entry",
        "description": (
            "Read one signed transparency-log entry by its sequence number. "
            "When that sequence has no entry, the result says a signed log entry is not available."
        ),
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "sequence": {
                    "type": "integer",
                    "minimum": 1,
                    "description": "Sequence number from the transparency log. The first entry is 1.",
                },
            },
            "required": ["sequence"],
        },
        "outputSchema": {
            "type": "object",
            "additionalProperties": True,
            "properties": {"entry": {"type": "object"}},
            "required": ["entry"],
        },
    },
)

_TOOL_SCOPE = {
    "verify_agent": "verify",
    "inquire": "inquire",
    "report": "report",
    "check_revocation": None,
    "fetch_signed_receipt": None,
}
_TOOL_RATE = {
    "verify_agent": "/v1/verify",
    "inquire": "/v1/inquiries",
    "report": "/v1/reports",
}
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


class _RpcFailure(Exception):
    def __init__(self, status: int, code: int, message: str, data: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.data = data


class _ToolFailure(Exception):
    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


def tools_for(auth) -> list[dict[str, Any]]:
    visible: list[dict[str, Any]] = []
    for tool in TOOLS:
        scope = _TOOL_SCOPE[tool["name"]]
        if scope is None or auth.admin or scope in auth.scopes:
            visible.append(tool)
    return visible


async def handle_mcp(request: Request, app: FastAPI) -> Response:
    """POST /mcp. One JSON-RPC message in, one JSON object out."""

    if not _origin_ok(request.headers.get("origin"), request.headers.get("host")):
        return _rpc(403, -32600, "origin is not allowed", ident=None, omit_id=True)
    try:
        payload = await _payload(request)
    except _RpcFailure as exc:
        return _rpc(exc.status, exc.code, exc.message, ident=None)
    if _is_notification(payload):
        try:
            bureau = ensure_bureau(app)
            _limit(request, bureau, app.state.settings, _bearer(request), payload.get("method"), None)
        except BureauError:
            return _rpc(503, -32603, "storage is unavailable", ident=None, omit_id=True)
        except _RpcFailure as exc:
            return _rpc(exc.status, exc.code, exc.message, ident=None, omit_id=True)
        return Response(status_code=202)
    try:
        ident = _request_id(payload)
        _check_version(request, payload)
        _check_method_header(request, payload)
        name = _check_tool_name_header(request, payload)
        _check_accept(request)
    except _RpcFailure as exc:
        return _rpc(exc.status, exc.code, exc.message, ident=_safe_id(payload), data=exc.data)

    token = _bearer(request)
    try:
        bureau = ensure_bureau(app)
    except BureauError:
        return _rpc(503, -32603, "storage is unavailable", ident=ident)
    settings = app.state.settings
    try:
        _limit(request, bureau, settings, token, payload.get("method"), name)
        method = payload.get("method")
        if method == "server/discover":
            result = _discover()
            status = 200
        elif method == "initialize":
            raise _RpcFailure(
                404,
                -32601,
                "This server supports protocol 2026-07-28. The initialize handshake is not used.",
            )
        elif method == "tools/list":
            auth = _api_key(request, bureau, settings, token)
            result = _tool_list(auth)
            status = 200
        elif method == "tools/call":
            auth = _api_key(request, bureau, settings, token)
            result = _tool_call(app, bureau, auth, name, payload, token)
            status = 200
        else:
            raise _RpcFailure(404, -32601, "Method not found")
        response = JSONResponse({"jsonrpc": "2.0", "id": ident, "result": result}, status_code=status)
    except _RpcFailure as exc:
        response = _rpc(
            exc.status,
            exc.code,
            _public_message(exc.message, token),
            ident=ident,
            data=exc.data,
            authenticate=exc.status == 401,
        )
    except _ToolFailure as exc:
        response = JSONResponse(
            {"jsonrpc": "2.0", "id": ident, "result": _error_result(_public_message(exc.message, token))},
            status_code=200,
        )
    except BureauError as exc:
        response = _bureau_error(exc, ident, token)
    except Exception:
        response = _rpc(500, -32603, "request failed", ident=ident)
    _audit(bureau, request, response.status_code, payload, name)
    return response


def _discover() -> dict[str, Any]:
    return {
        "resultType": "complete",
        "supportedVersions": [PROTOCOL_VERSION],
        "capabilities": {"tools": {}},
        "instructions": (
            "Global Agent Bureau is an agent bureau. "
            "verify_agent checks an action. inquire reads an agent. report files an outcome. "
            "check_revocation reads the public revocation list. "
            "fetch_signed_receipt reads one signed log entry. "
            "A gab_test_ key stays in the test partition and does not change a production score."
        ),
        "ttlMs": 3_600_000,
        "cacheScope": "public",
        "_meta": _SERVER_INFO,
    }


def _tool_list(auth) -> dict[str, Any]:
    return {
        "resultType": "complete",
        "tools": tools_for(auth),
        "ttlMs": 300_000,
        "cacheScope": "private",
    }


def _tool_call(app: FastAPI, bureau, auth, name: str | None, payload: dict[str, Any], token: str) -> dict[str, Any]:
    if name not in _TOOL_SCOPE:
        raise _RpcFailure(400, -32602, f"Unknown tool: {name}")
    scope = _TOOL_SCOPE[name]
    if scope is not None and not auth.admin and scope not in auth.scopes:
        raise _RpcFailure(403, -32001, "missing scope")
    params = payload.get("params")
    if not isinstance(params, dict):
        raise _RpcFailure(400, -32602, "params must be an object")
    arguments = params.get("arguments", {})
    if arguments is None:
        arguments = {}
    if not isinstance(arguments, dict):
        raise _RpcFailure(400, -32602, "arguments must be an object")
    mode = use_test_mode(bool(auth.test))
    try:
        if name == "verify_agent":
            produced = bureau.verify(auth, _verify_body(arguments))
        elif name == "inquire":
            produced = bureau.inquire(auth, _inquire_body(arguments))
        elif name == "report":
            produced = bureau.report(auth, _report_body(arguments))
        elif name == "check_revocation":
            produced = _revocations(auth, arguments, bureau, getattr(app.state, "store", None))
        else:
            produced = _receipt(arguments, getattr(app.state, "store", None))
    finally:
        reset_test_mode(mode)
    clean = _scrub(_plain(produced), token)
    return {
        "resultType": "complete",
        "content": [{"type": "text", "text": json.dumps(clean, sort_keys=True, separators=(",", ":"))}],
        "structuredContent": clean,
        "isError": False,
    }


def _verify_body(arguments: dict[str, Any]) -> dict[str, Any]:
    _only(arguments, {"agent_id", "action", "agreement_id", "intent_id"})
    action = arguments.get("action")
    if not isinstance(action, dict):
        raise _ToolFailure("action must be an object")
    body: dict[str, Any] = {"agent_id": _text(arguments, "agent_id"), "action": action}
    if "agreement_id" in arguments:
        body["agreement_id"] = _text(arguments, "agreement_id")
    if "intent_id" in arguments:
        body["intent_id"] = _text(arguments, "intent_id")
    return body


def _inquire_body(arguments: dict[str, Any]) -> dict[str, Any]:
    _only(arguments, {"agent_id", "purpose_code"})
    return {"agent_id": _text(arguments, "agent_id"), "purpose_code": _text(arguments, "purpose_code")}


def _report_body(arguments: dict[str, Any]) -> dict[str, Any]:
    _only(arguments, {"agent_id", "kind", "evidence_hash", "summary", "outcome", "action_id"})
    body: dict[str, Any] = {
        "agent_id": _text(arguments, "agent_id"),
        "kind": _text(arguments, "kind"),
        "evidence_hash": _text(arguments, "evidence_hash"),
        "summary": _text(arguments, "summary"),
    }
    if "outcome" in arguments:
        body["outcome"] = _text(arguments, "outcome")
    if "action_id" in arguments:
        body["action_id"] = _text(arguments, "action_id")
    return body


def _revocations(auth, arguments: dict[str, Any], bureau, store) -> dict[str, Any]:
    _only(arguments, {"agent_id"})
    if store is None:
        raise _ToolFailure("revocation list is not available")
    try:
        rows = store.list_revocations()
    except Exception as exc:
        raise _ToolFailure("revocation list is not available") from exc
    result: dict[str, Any] = {"revocations": rows}
    if "agent_id" in arguments:
        view = bureau.get_agent(auth, _text(arguments, "agent_id"))
        result["agent"] = {
            "agent_id": view.get("agent_id"),
            "status": view.get("status"),
            "environment": view.get("environment"),
        }
    return result


def _receipt(arguments: dict[str, Any], store) -> dict[str, Any]:
    _only(arguments, {"sequence"})
    sequence = arguments.get("sequence")
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 1:
        raise _ToolFailure("sequence must be a positive integer")
    if store is None:
        raise _ToolFailure("a signed log entry is not available")
    try:
        entry = store.get_entry(sequence)
    except Exception as exc:
        raise _ToolFailure("a signed log entry is not available") from exc
    if entry is None:
        raise _ToolFailure("a signed log entry is not available")
    return {"entry": entry}


def _api_key(request: Request, bureau, settings, token: str):
    if not token:
        raise _RpcFailure(401, -32001, "credentials are required")
    auth = bureau.authenticate(token, admin_token=settings.admin_token)
    if auth.kind not in {"key", "admin"}:
        raise _RpcFailure(401, -32001, "an api key is required")
    request.state.org_id = auth.org_id
    request.state.key_id = auth.key_id
    request.state.environment = "test" if auth.test else "live"
    return auth


def _limit(request: Request, bureau, settings, token: str, method: Any, name: str | None) -> None:
    subject = token_hash(token) if token else (request.client.host if request.client else "anonymous")
    if bureau.hit_rate(subject) > settings.rate_limit_per_minute:
        raise _RpcFailure(429, -32000, "rate limit exceeded")
    if method != "tools/call" or name not in _TOOL_RATE:
        return
    path = _TOOL_RATE[name]
    cap = _endpoint_rate_cap("POST", path, settings)
    if cap is not None and bureau.hit_rate(f"{path}:{subject}") > cap:
        raise _RpcFailure(429, -32000, "rate limit exceeded")


def _audit(bureau, request: Request, status: int, payload: dict[str, Any], name: str | None) -> None:
    params = payload.get("params") if isinstance(payload.get("params"), dict) else {}
    arguments = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
    agent_id = arguments.get("agent_id")
    if not isinstance(agent_id, str) or len(agent_id) > 80:
        agent_id = None
    purpose = arguments.get("purpose_code") if isinstance(arguments.get("purpose_code"), str) else None
    path = "/mcp"
    if isinstance(name, str) and name in _TOOL_SCOPE:
        path = f"/mcp/{name}"
    try:
        auth_state = getattr(request.state, "org_id", None)
        bureau.repo.add_audit(
            {
                "audit_id": "aud_" + secrets.token_hex(8),
                "at": bureau.stamp(),
                "org_id": auth_state,
                "key_id": getattr(request.state, "key_id", None),
                "method": "POST",
                "path": path,
                "status": status,
                "purpose_code": purpose,
                "agent_id": agent_id,
                "environment": "test" if getattr(request.state, "environment", None) == "test" else "live",
            }
        )
    except Exception:
        return


def _check_version(request: Request, payload: dict[str, Any]) -> None:
    header = request.headers.get("mcp-protocol-version")
    if not header:
        raise _RpcFailure(400, -32020, "MCP-Protocol-Version header is required")
    meta = _meta(payload)
    body_version = meta.get(_META_VERSION)
    if not isinstance(body_version, str) or body_version != header:
        raise _RpcFailure(400, -32020, "MCP-Protocol-Version does not match the body")
    if header != PROTOCOL_VERSION:
        raise _RpcFailure(
            400,
            -32022,
            "Unsupported protocol version",
            {"supported": [PROTOCOL_VERSION], "requested": header},
        )


def _check_method_header(request: Request, payload: dict[str, Any]) -> None:
    header = request.headers.get("mcp-method")
    method = payload.get("method")
    if not isinstance(method, str) or not header or header != method:
        raise _RpcFailure(400, -32020, "Mcp-Method header does not match the body")


def _check_tool_name_header(request: Request, payload: dict[str, Any]) -> str | None:
    if payload.get("method") != "tools/call":
        return None
    params = payload.get("params")
    name = params.get("name") if isinstance(params, dict) else None
    header = request.headers.get("mcp-name")
    if not isinstance(name, str) or not header:
        raise _RpcFailure(400, -32020, "Mcp-Name header is required")
    try:
        decoded = _decode_header(header)
    except ValueError as exc:
        raise _RpcFailure(400, -32020, "Mcp-Name header is not valid") from exc
    if decoded != name:
        raise _RpcFailure(400, -32020, "Mcp-Name header does not match the body")
    return name


def _check_accept(request: Request) -> None:
    accept = request.headers.get("accept")
    if accept is None:
        return
    folded = accept.lower()
    if "application/json" not in folded and "*/*" not in folded:
        raise _RpcFailure(406, -32600, "Accept must allow application/json")


def _origin_ok(origin: str | None, host: str | None) -> bool:
    if not origin:
        return True
    parsed = urlparse(origin)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return False
    request_host = (host or "").split(",")[0].strip().split(":")[0].lower()
    origin_host = parsed.hostname.lower()
    if origin_host == request_host:
        return True
    return request_host in _LOCAL_HOSTS and origin_host in _LOCAL_HOSTS


def _decode_header(value: str) -> str:
    if value.startswith("=?base64?") and value.endswith("?="):
        raw = value[len("=?base64?") : -2]
        try:
            return base64.b64decode(raw, validate=True).decode("utf-8")
        except Exception as exc:
            raise ValueError("bad header") from exc
    return value


async def _payload(request: Request) -> dict[str, Any]:
    raw = await request.body()
    if not raw:
        raise _RpcFailure(400, -32700, "parse error")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise _RpcFailure(400, -32700, "parse error") from exc
    if not isinstance(payload, dict):
        raise _RpcFailure(400, -32600, "invalid request")
    if payload.get("jsonrpc") != "2.0":
        raise _RpcFailure(400, -32600, "invalid request")
    return payload


def _is_notification(payload: dict[str, Any]) -> bool:
    return "id" not in payload and isinstance(payload.get("method"), str)


def _request_id(payload: dict[str, Any]) -> Any:
    ident = payload.get("id")
    if ident is None or isinstance(ident, str) or (isinstance(ident, int) and not isinstance(ident, bool)):
        return ident
    raise _RpcFailure(400, -32600, "invalid request")


def _safe_id(payload: dict[str, Any]) -> Any:
    ident = payload.get("id")
    if ident is None or isinstance(ident, str) or (isinstance(ident, int) and not isinstance(ident, bool)):
        return ident
    return None


def _meta(payload: dict[str, Any]) -> dict[str, Any]:
    params = payload.get("params")
    if not isinstance(params, dict):
        return {}
    meta = params.get("_meta")
    if not isinstance(meta, dict):
        return {}
    return meta


def _bearer(request: Request) -> str:
    header = request.headers.get("authorization", "")
    prefix = "Bearer "
    if not header.startswith(prefix):
        return ""
    return header[len(prefix) :].strip()


def _only(arguments: dict[str, Any], allowed: set[str]) -> None:
    extra = set(arguments) - allowed
    if extra:
        raise _ToolFailure("unknown argument")


def _text(arguments: dict[str, Any], key: str) -> str:
    value = arguments.get(key)
    if not isinstance(value, str) or not value.strip():
        raise _ToolFailure(f"{key} must be a string")
    return value


def _error_result(message: str) -> dict[str, Any]:
    return {
        "resultType": "complete",
        "content": [{"type": "text", "text": message}],
        "isError": True,
    }


def _bureau_error(exc: BureauError, ident: Any, token: str) -> JSONResponse:
    message = _public_message(exc.message, token)
    if exc.status in {400, 404}:
        return JSONResponse({"jsonrpc": "2.0", "id": ident, "result": _error_result(message)}, status_code=200)
    if exc.status >= 500:
        message = "request failed"
    code = -32001 if exc.status in {401, 403} else -32000
    return _rpc(exc.status, code, message, ident=ident, authenticate=exc.status == 401)


def _public_message(message: str, token: str) -> str:
    if token and token in message:
        return "request failed"
    lowered = message.lower()
    if "password" in lowered or "secret_hash" in lowered or "database_url" in lowered:
        return "request failed"
    return message


def _scrub(value: Any, token: str) -> Any:
    if isinstance(value, str):
        if token and token in value:
            return "request failed"
        return value
    if isinstance(value, dict):
        return {str(key): _scrub(item, token) for key, item in value.items() if str(key).lower() not in _HIDDEN_KEYS}
    if isinstance(value, list):
        return [_scrub(item, token) for item in value]
    return value


def _rpc(
    status: int,
    code: int,
    message: str,
    *,
    ident: Any,
    data: dict[str, Any] | None = None,
    omit_id: bool = False,
    authenticate: bool = False,
) -> JSONResponse:
    error: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    body: dict[str, Any] = {"jsonrpc": "2.0", "error": error}
    if not omit_id:
        body["id"] = ident
    headers: dict[str, str] = {}
    if authenticate:
        headers["WWW-Authenticate"] = "Bearer"
    if status == 429:
        headers["Retry-After"] = "60"
    return JSONResponse(body, status_code=status, headers=headers or None)
