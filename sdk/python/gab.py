# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Small client for the Global Agent Bureau API.

The key stays in memory and is not written to logs by this module.
"""

from __future__ import annotations

import json
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

_ALERT_TYP = "kata-bureau-alert+jws"


class GabError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


class Client:
    def __init__(self, api_key: str, base_url: str = "https://globalagentbureau.com", timeout: float = 10) -> None:
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def register_agent(self, body: dict[str, Any]) -> dict[str, Any]:
        return self._request("POST", "/v1/agents", body)

    def verify(
        self,
        agent_id: str,
        action: dict[str, Any],
        *,
        intent_id: str | None = None,
        agreement_id: str | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {"agent_id": agent_id, "action": action}
        if intent_id:
            payload["intent_id"] = intent_id
        if agreement_id:
            payload["agreement_id"] = agreement_id
        return self._request("POST", "/v1/verify", payload)

    def inquire(self, agent_id: str, purpose_code: str) -> dict[str, Any]:
        return self._request("POST", "/v1/inquiries", {"agent_id": agent_id, "purpose_code": purpose_code})

    def report(
        self,
        agent_id: str,
        kind: str,
        evidence_hash: str,
        summary: str,
        *,
        action_id: str | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "agent_id": agent_id,
            "kind": kind,
            "evidence_hash": evidence_hash,
            "summary": summary,
        }
        if action_id:
            payload["action_id"] = action_id
        return self._request("POST", "/v1/reports", payload)

    def subscribe(self, agent_id: str, webhook_url: str) -> dict[str, Any]:
        return self._request("POST", "/v1/subscriptions", {"agent_id": agent_id, "webhook_url": webhook_url})

    def published_keys(self) -> list[dict[str, Any]]:
        payload = self._request("GET", "/.well-known/kata-keys.json", auth=False)
        keys = payload.get("keys")
        if not isinstance(keys, list):
            raise GabError(502, "key list was missing")
        return keys

    def _request(self, method: str, path: str, body: dict[str, Any] | None = None, *, auth: bool = True) -> dict[str, Any]:
        data = None if body is None else json.dumps(body).encode("utf-8")
        headers = {"Accept": "application/json", "User-Agent": "gab-sdk/0.1"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        if auth:
            headers["Authorization"] = f"Bearer {self.api_key}"
        request = Request(self.base_url + path, data=data, headers=headers, method=method)
        try:
            with urlopen(request, timeout=self.timeout) as response:
                raw = response.read()
        except HTTPError as exc:
            raw = exc.read()
            raise GabError(exc.code, _error_message(raw, self.api_key)) from None
        except URLError:
            raise GabError(503, "the bureau did not answer") from None
        return _json_object(raw, self.api_key)


def verify_alert(message: dict[str, Any], public_jwk: dict[str, Any]) -> dict[str, Any]:
    """Return the signed alert object, or raise when the JWS does not match."""

    from kata_intent.jws import verify_jws
    from kata_intent.keys import public_key_from_jwk

    if not isinstance(message, dict) or not isinstance(public_jwk, dict):
        raise GabError(401, "alert signature was not accepted")
    signature = message.get("signature")
    try:
        check = verify_jws(signature, public_key_from_jwk(public_jwk), typ=_ALERT_TYP)
    except Exception:
        raise GabError(401, "alert signature was not accepted") from None
    if not check.ok or not isinstance(check.payload, dict):
        raise GabError(401, "alert signature was not accepted")
    unsigned = {key: value for key, value in message.items() if key != "signature"}
    if unsigned != check.payload:
        raise GabError(401, "alert signature was not accepted")
    return check.payload


def _json_object(raw: bytes, secret: str) -> dict[str, Any]:
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        raise GabError(502, "response was not json") from None
    if not isinstance(payload, dict):
        raise GabError(502, "response was not json")
    text = json.dumps(payload)
    if secret and secret in text:
        raise GabError(502, "response was not accepted")
    return payload


def _error_message(raw: bytes, secret: str) -> str:
    try:
        payload = json.loads(raw.decode("utf-8"))
        message = str(payload.get("error") or "request failed")
    except (UnicodeError, json.JSONDecodeError, AttributeError):
        message = "request failed"
    if secret and secret in message:
        return "request failed"
    return message
