# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: Apache-2.0
"""Intent-agreement lifecycle.

The mandate is what the principal signs. The agreement is the record around
it: proposals, clarifications, acceptance, acknowledgements, amendments,
revocation, and expiry. Event hashes chain backward so an edit in the middle
no longer matches. The chain does not stop someone who holds the file from
dropping the tail. Revocation is a separate signature, and a verifier that
needs to know the grant is still live has to check a source other than the
copy the agent presents.
"""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from typing import Any

from kata_intent.canonical import canonical_bytes
from kata_intent.document import (
    acknowledgement_document,
    draft_document,
    mandate_hash,
    revocation_document,
    signing_document,
)
from kata_intent.errors import KataError
from kata_intent.jws import same_bytes, sign_jws, verify_jws
from kata_intent.keys import PrivateKey, PublicKey, public_key_from_jwk
from kata_intent.render import render_mandate
from kata_intent.values import (
    ACK_ROLES,
    ACTOR_ROLES,
    CURRENCY,
    FREQUENCY,
    as_time,
    coerce,
    hash_document,
    money,
    parse_time,
    prefixed_hash,
    require_text,
    text_hash,
)

MANDATE_TYP = "kata-mandate+jws"
ACK_TYP = "kata-ack+jws"
REVOCATION_TYP = "kata-revocation+jws"


@dataclass(frozen=True)
class Actor:
    """Who performed a lifecycle step."""

    role: str
    id: str

    def __post_init__(self) -> None:
        if self.role not in ACTOR_ROLES:
            raise KataError(f"unknown actor role: {self.role}")
        require_text(self.id, "actor id")


class Agreement:
    """One intent agreement and its audit log."""

    def __init__(self, record: dict[str, Any]):
        self._record = record

    @classmethod
    def propose(
        cls,
        *,
        agreement_id: str,
        principal: dict[str, Any],
        agent: dict[str, Any],
        agent_public_key: PublicKey,
        intent: dict[str, Any],
        actor: Actor,
        at: str | Any,
        delegation_id: str | None = None,
        limits: dict[str, Any] | None = None,
        not_before: str | None = None,
        expires_at: str | None = None,
        required_acknowledgements: list[str] | None = None,
        revocation_endpoint: str | None = None,
        note: str | None = None,
    ) -> Agreement:
        """Open an unsigned agreement. The principal has not signed yet."""

        require_text(agreement_id, "agreement_id")
        _validate_party(principal, "principal")
        if not isinstance(agent, dict) or not agent.get("agent_id"):
            raise KataError("agent.agent_id is required")
        intent = _validate_intent(coerce(intent))
        limits = _validate_limits(coerce(limits) if limits else None, intent)
        acks = list(required_acknowledgements or [])
        for role in acks:
            if role not in ACK_ROLES:
                raise KataError(f"cannot require an acknowledgement from {role}")
        stamped = as_time(at)
        mandate: dict[str, Any] = {
            "agent": {
                "agent_id": agent["agent_id"],
                "public_key": agent_public_key.to_jwk(),
                "public_key_fingerprint": agent_public_key.fingerprint,
            },
            "intent": intent,
            "mandate_id": f"{agreement_id}.v1",
            "principal": {key: principal[key] for key in ("display_name", "id", "type") if key in principal},
            "version": 1,
        }
        if delegation_id:
            mandate["delegation_id"] = require_text(delegation_id, "delegation_id")
        if expires_at:
            mandate["expires_at"] = as_time(expires_at)
        if limits:
            mandate["limits"] = limits
        if not_before:
            mandate["not_before"] = as_time(not_before)
        if acks:
            mandate["required_acknowledgements"] = acks
        if revocation_endpoint:
            mandate["revocation_endpoint"] = require_text(revocation_endpoint, "revocation_endpoint")
        _check_window_consistency(mandate)
        agreement = cls(
            {
                "acknowledgements": [],
                "agreement_id": agreement_id,
                "created_at": stamped,
                "events": [],
                "mandate": mandate,
                "mandate_history": [],
                "status": "proposed",
                "updated_at": stamped,
            }
        )
        agreement._append_event(
            type="proposed",
            actor=actor,
            at=stamped,
            mandate_hash=hash_document(draft_document(mandate)),
            note=note,
        )
        return agreement

    @classmethod
    def from_dict(cls, record: dict[str, Any]) -> Agreement:
        if not isinstance(record, dict) or "agreement_id" not in record or "mandate" not in record:
            raise KataError("agreement record is missing agreement_id or mandate")
        return cls(coerce(record))

    @classmethod
    def from_json(cls, text: str) -> Agreement:
        return cls.from_dict(json.loads(text, parse_float=_decimal, parse_int=int))

    def to_dict(self) -> dict[str, Any]:
        return coerce(self._record)

    def to_json(self) -> str:
        return canonical_bytes(self.to_dict()).decode("utf-8")

    @property
    def status(self) -> str:
        return self._record["status"]

    @property
    def agreement_id(self) -> str:
        return self._record["agreement_id"]

    @property
    def mandate(self) -> dict[str, Any]:
        return self._record["mandate"]

    @property
    def events(self) -> list[dict[str, Any]]:
        return self._record["events"]

    @property
    def log_head(self) -> str | None:
        if not self.events:
            return None
        return self.events[-1]["event_hash"]

    def rendering_preview(self) -> str:
        """The text the principal should read before ``accept``."""

        return render_mandate(self.mandate)

    def update_draft(
        self,
        *,
        actor: Actor,
        at: str | Any,
        intent: dict[str, Any] | None = None,
        limits: dict[str, Any] | None = None,
        not_before: str | None = None,
        expires_at: str | None = None,
        note: str | None = None,
    ) -> None:
        """Replace unsigned terms. This is the clarify / negotiate step."""

        self._require_status("proposed", "clarifying")
        mandate = self.mandate
        if intent:
            merged = dict(mandate["intent"])
            merged.update(coerce(intent))
            merged["version"] = mandate["version"]
            mandate["intent"] = _validate_intent(merged)
        if limits is not None:
            mandate["limits"] = _validate_limits(coerce(limits), mandate["intent"])
        if not_before is not None:
            mandate["not_before"] = as_time(not_before)
        if expires_at is not None:
            mandate["expires_at"] = as_time(expires_at)
        _check_window_consistency(mandate)
        self._record["status"] = "clarifying"
        self._append_event(
            type="clarified",
            actor=actor,
            at=as_time(at),
            mandate_hash=hash_document(draft_document(mandate)),
            note=note,
        )

    def accept(self, principal_key: PrivateKey, at: str | Any, *, confirmed_text: str | None = None) -> None:
        """Principal signs the current draft. Matching ``confirmed_text`` binds the words they were shown."""

        self._require_status("proposed", "clarifying")
        mandate = self.mandate
        mandate["principal"]["public_key"] = principal_key.public.to_jwk()
        text = render_mandate(mandate)
        if confirmed_text is not None and confirmed_text != text:
            mandate["principal"].pop("public_key", None)
            raise KataError("confirmed text does not match the mandate rendering")
        mandate["rendering"] = {"hash": text_hash(text), "text": text}
        signed = signing_document(mandate)
        mandate["signature"] = sign_jws(signed, principal_key, typ=MANDATE_TYP)
        stamped = as_time(at)
        self._append_event(
            type="accepted",
            actor=Actor("principal", mandate["principal"]["id"]),
            at=stamped,
            mandate_hash=hash_document(signed),
        )
        if self._required_roles_met():
            self._record["status"] = "active"
            self._append_event(
                type="activated",
                actor=Actor("principal", mandate["principal"]["id"]),
                at=stamped,
                mandate_hash=hash_document(signed),
            )
        else:
            self._record["status"] = "accepted"

    def acknowledge(
        self,
        *,
        role: str,
        party_id: str,
        private_key: PrivateKey,
        at: str | Any,
        note: str | None = None,
    ) -> None:
        """Countersign the current mandate hash. This is the optional counterparty acknowledgement."""

        self._require_status("accepted", "active")
        if role not in ACK_ROLES:
            raise KataError(f"cannot acknowledge as {role}")
        if self.mandate.get("signature") is None:
            raise KataError("cannot acknowledge an unsigned mandate")
        if role == "agent" and party_id != self.mandate["agent"]["agent_id"]:
            raise KataError("agent acknowledgement id does not match the bound agent")
        if role == "agent" and private_key.public.fingerprint != self.mandate["agent"]["public_key_fingerprint"]:
            raise KataError("agent acknowledgement key does not match the bound agent")
        current = mandate_hash(self.mandate)
        document = {
            "agreement_id": self.agreement_id,
            "at": as_time(at),
            "id": require_text(party_id, "party id"),
            "kata_ack": "1",
            "mandate_hash": current,
            "public_key": private_key.public.to_jwk(),
            "role": role,
        }
        acknowledgement = dict(document)
        acknowledgement["signature"] = sign_jws(document, private_key, typ=ACK_TYP)
        self._record["acknowledgements"].append(acknowledgement)
        self._append_event(
            type="acknowledged",
            actor=Actor(role, party_id),
            at=document["at"],
            mandate_hash=current,
            note=note,
            detail={"role": role},
        )
        if self.status == "accepted" and self._required_roles_met():
            self._record["status"] = "active"
            self._append_event(
                type="activated",
                actor=Actor(role, party_id),
                at=document["at"],
                mandate_hash=current,
            )

    def amend(
        self,
        principal_key: PrivateKey,
        at: str | Any,
        *,
        intent: dict[str, Any] | None = None,
        limits: dict[str, Any] | None = None,
        not_before: str | None = None,
        expires_at: str | None = None,
        note: str | None = None,
        confirmed_text: str | None = None,
    ) -> None:
        """Sign a new mandate version. The previous version stays in the history and is no longer active."""

        self._require_status("active")
        self._require_principal_key(principal_key)
        previous = mandate_hash(self.mandate)
        self._record["mandate_history"].append(self.mandate)
        version = int(self.mandate["version"]) + 1
        updated = copy.deepcopy(self.mandate)
        updated.pop("signature", None)
        updated.pop("rendering", None)
        updated["version"] = version
        updated["supersedes"] = previous
        updated["mandate_id"] = f"{self.agreement_id}.v{version}"
        if intent:
            merged = dict(updated["intent"])
            merged.update(coerce(intent))
            updated["intent"] = merged
        updated["intent"]["version"] = version
        updated["intent"] = _validate_intent(updated["intent"])
        if limits is not None:
            updated["limits"] = _validate_limits(coerce(limits), updated["intent"])
        elif updated.get("limits"):
            # The restated per-transaction ceiling follows the amended intent.
            updated["limits"].pop("per_transaction_maximum", None)
            updated["limits"] = _validate_limits(updated["limits"], updated["intent"])
        if not_before is not None:
            updated["not_before"] = as_time(not_before)
        if expires_at is not None:
            updated["expires_at"] = as_time(expires_at)
        _check_window_consistency(updated)
        updated["principal"]["public_key"] = principal_key.public.to_jwk()
        text = render_mandate(updated)
        if confirmed_text is not None and confirmed_text != text:
            raise KataError("confirmed text does not match the amended rendering")
        updated["rendering"] = {"hash": text_hash(text), "text": text}
        signed = signing_document(updated)
        updated["signature"] = sign_jws(signed, principal_key, typ=MANDATE_TYP)
        self._record["mandate"] = updated
        self._record["acknowledgements"] = []
        stamped = as_time(at)
        current = hash_document(signed)
        self._append_event(
            type="amended",
            actor=Actor("principal", updated["principal"]["id"]),
            at=stamped,
            mandate_hash=current,
            note=note,
            detail={"supersedes": previous, "version": version},
        )
        if self._required_roles_met():
            self._record["status"] = "active"
        else:
            self._record["status"] = "accepted"

    def revoke(self, principal_key: PrivateKey, at: str | Any, *, reason: str = "principal_request") -> dict[str, Any]:
        """Sign a revocation. Returns the revocation object, which a verifier can store outside this record."""

        self._require_status("proposed", "clarifying", "accepted", "active")
        if self.mandate.get("signature"):
            self._require_principal_key(principal_key)
        current = mandate_hash(self.mandate) if self.mandate.get("signature") else hash_document(draft_document(self.mandate))
        document = {
            "agreement_id": self.agreement_id,
            "at": as_time(at),
            "kata_revocation": "1",
            "mandate_hash": current,
            "reason": require_text(reason, "reason"),
        }
        revocation = dict(document)
        revocation["signature"] = sign_jws(document, principal_key, typ=REVOCATION_TYP)
        self._record["revocation"] = revocation
        self._record["status"] = "revoked"
        self._append_event(
            type="revoked",
            actor=Actor("principal", self.mandate["principal"]["id"]),
            at=document["at"],
            mandate_hash=current,
            detail={"reason": reason},
        )
        return revocation

    def expire(self, at: str | Any) -> None:
        """Record expiry once ``at`` is past the mandate window. Evaluation also enforces the window on its own."""

        self._require_status("proposed", "clarifying", "accepted", "active")
        stamped = as_time(at)
        expires_at = self.mandate.get("expires_at") or (self.mandate.get("intent") or {}).get("time_limit")
        if not expires_at:
            raise KataError("agreement has no expiry")
        if parse_time(stamped) <= parse_time(expires_at):
            raise KataError("agreement has not expired")
        self._record["status"] = "expired"
        self._append_event(
            type="expired",
            actor=Actor("policy", "expiry"),
            at=stamped,
            mandate_hash=mandate_hash(self.mandate),
        )

    def _require_status(self, *allowed: str) -> None:
        if self.status not in allowed:
            raise KataError(f"cannot do that while the agreement is {self.status}")

    def _require_principal_key(self, key: PrivateKey) -> None:
        embedded = (self.mandate.get("principal") or {}).get("public_key")
        if not embedded:
            raise KataError("mandate has no principal public key")
        if public_key_from_jwk(embedded).fingerprint != key.public.fingerprint:
            raise KataError("principal key does not match the signed mandate")

    def _required_roles_met(self) -> bool:
        required = set(self.mandate.get("required_acknowledgements") or [])
        if not required:
            return True
        current = mandate_hash(self.mandate)
        seen = set()
        for ack in self._record["acknowledgements"]:
            if ack.get("mandate_hash") == current and ack.get("role") in required:
                check = verify_jws(ack.get("signature") or {}, _ack_key(ack), typ=ACK_TYP)
                if check.ok and check.payload_bytes and same_bytes(
                    check.payload_bytes, canonical_bytes(acknowledgement_document(ack))
                ):
                    seen.add(ack["role"])
        return required <= seen

    def _append_event(
        self,
        *,
        type: str,
        actor: Actor,
        at: str,
        mandate_hash: str,
        note: str | None = None,
        detail: dict[str, Any] | None = None,
    ) -> None:
        body: dict[str, Any] = {
            "actor": {"id": actor.id, "role": actor.role},
            "agreement_id": self.agreement_id,
            "at": at,
            "event_id": f"evt_{len(self.events) + 1:04d}",
            "mandate_hash": mandate_hash,
            "type": type,
        }
        if detail is not None:
            body["detail"] = detail
        if note:
            body["note"] = note
        if self.events:
            body["prev_event_hash"] = self.events[-1]["event_hash"]
        body["event_hash"] = prefixed_hash(canonical_bytes(body))
        self.events.append(body)
        self._record["updated_at"] = at


def verify_event_chain(events: list[dict[str, Any]]) -> bool:
    """True when each event hash matches its body and points at the previous event."""

    previous: str | None = None
    for event in events:
        if not isinstance(event, dict) or "event_hash" not in event:
            return False
        body = {key: value for key, value in event.items() if key != "event_hash"}
        if previous is None:
            if "prev_event_hash" in body:
                return False
        elif body.get("prev_event_hash") != previous:
            return False
        if event["event_hash"] != prefixed_hash(canonical_bytes(body)):
            return False
        previous = event["event_hash"]
    return True


def verify_revocation(revocation: dict[str, Any], public_key: PublicKey) -> bool:
    """True when ``revocation`` is a signature by ``public_key`` over its own fields."""

    if not isinstance(revocation, dict) or "signature" not in revocation:
        return False
    check = verify_jws(revocation["signature"], public_key, typ=REVOCATION_TYP)
    if not check.ok or check.payload_bytes is None:
        return False
    return same_bytes(check.payload_bytes, canonical_bytes(revocation_document(revocation)))


def _ack_key(ack: dict[str, Any]) -> PublicKey:
    return public_key_from_jwk(ack["public_key"])


def _validate_party(principal: dict[str, Any], label: str) -> None:
    if not isinstance(principal, dict):
        raise KataError(f"{label} must be an object")
    if principal.get("type") not in {"human", "business", "institution", "system", "agent"}:
        raise KataError(f"{label} type is not a KATA principal type")
    require_text(principal.get("id"), f"{label} id")


def _validate_intent(intent: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(intent, dict):
        raise KataError("intent must be an object")
    require_text(intent.get("intent_id"), "intent_id")
    require_text(intent.get("purpose"), "purpose")
    version = intent.get("version")
    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
        raise KataError("intent.version must be an integer >= 1")
    currency = intent.get("currency")
    if currency is not None and (not isinstance(currency, str) or not CURRENCY.match(currency)):
        raise KataError("currency must be an ISO 4217 code")
    if intent.get("maximum_amount") is not None:
        amount = money(intent["maximum_amount"])
        if amount < 0:
            raise KataError("maximum_amount cannot be negative")
        intent["maximum_amount"] = amount
    time_limit = intent.get("time_limit")
    if time_limit is not None:
        intent["time_limit"] = as_time(time_limit)
    return intent


def _validate_limits(limits: dict[str, Any] | None, intent: dict[str, Any]) -> dict[str, Any] | None:
    if limits is None:
        limits = {}
    if not isinstance(limits, dict):
        raise KataError("limits must be an object")
    if intent.get("currency") and "currency" not in limits:
        limits["currency"] = intent["currency"]
    currency = limits.get("currency")
    if currency is not None and (not isinstance(currency, str) or not CURRENCY.match(currency)):
        raise KataError("limits.currency must be an ISO 4217 code")
    if intent.get("currency") and currency and currency != intent["currency"]:
        raise KataError("limits.currency does not match the intent currency")
    ceiling = intent.get("maximum_amount")
    stated = limits.get("per_transaction_maximum")
    if ceiling is not None:
        if stated is not None and money(stated) != money(ceiling):
            raise KataError("per_transaction_maximum does not match intent.maximum_amount")
        limits["per_transaction_maximum"] = money(ceiling)
    elif stated is not None:
        limits["per_transaction_maximum"] = money(stated)
    if limits.get("cumulative_maximum") is not None:
        cumulative = money(limits["cumulative_maximum"])
        if cumulative < 0:
            raise KataError("cumulative_maximum cannot be negative")
        limits["cumulative_maximum"] = cumulative
    frequency = limits.get("frequency")
    if frequency is not None:
        if not isinstance(frequency, dict):
            raise KataError("frequency must be an object")
        count = frequency.get("max_count")
        if isinstance(count, bool) or not isinstance(count, int) or count < 1:
            raise KataError("frequency.max_count must be an integer >= 1")
        per = frequency.get("per")
        if per not in FREQUENCY:
            raise KataError("frequency.per must be agreement, P1D, P7D, or P1M")
        limits["frequency"] = {"max_count": count, "per": per}
    denylist = limits.get("merchant_denylist")
    if denylist is not None:
        if not isinstance(denylist, list) or not all(isinstance(item, str) for item in denylist):
            raise KataError("merchant_denylist must be a list of strings")
    if not limits:
        return None
    return limits


def _check_window_consistency(mandate: dict[str, Any]) -> None:
    expires_at = mandate.get("expires_at")
    time_limit = (mandate.get("intent") or {}).get("time_limit")
    if expires_at and time_limit and as_time(expires_at) != as_time(time_limit):
        raise KataError("expires_at and intent.time_limit disagree")
    if mandate.get("not_before") and expires_at and parse_time(mandate["not_before"]) > parse_time(expires_at):
        raise KataError("not_before is after expiry")


def _decimal(value: str):
    from decimal import Decimal

    return Decimal(value)
