# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: Apache-2.0
"""Intent-agreement lifecycle.

The mandate is what the principal signs. The agreement is the record around
one or more live mandates, and it is stored inside the delegation. The
agreement also holds the spend ledger. Event hashes chain backward so an
edit in the middle no longer matches. The chain does not stop someone who
holds the file from dropping the tail. Revocation is a separate signature,
and a verifier that needs to know the grant is still live has to check a
source other than the copy the agent presents.
"""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from decimal import Decimal
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
    """One intent agreement, its live intents, its spend ledger, and its audit log."""

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
        parent_limits: dict[str, Any] | None = None,
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
        parent = _initial_parent(intent, limits, parent_limits, mandate.get("expires_at"))
        mandate["parent_limits"] = parent
        _check_window_consistency(mandate)
        agreement = cls(
            {
                "acknowledgements": [],
                "agreement_id": agreement_id,
                "created_at": stamped,
                "events": [],
                "ledger": [],
                "mandate_history": [],
                "mandates": [mandate],
                "parent_limits": parent,
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
        if not isinstance(record, dict) or "agreement_id" not in record:
            raise KataError("agreement record is missing agreement_id or mandate")
        record = coerce(record)
        if "mandates" not in record and isinstance(record.get("mandate"), dict):
            record["mandates"] = [record.pop("mandate")]
        if not isinstance(record.get("mandates"), list) or not record["mandates"]:
            raise KataError("agreement record is missing agreement_id or mandate")
        record.pop("mandate", None)
        return cls(record)

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
        """The only live mandate. Raises when several intents are live."""

        return self._select(None)

    @property
    def mandates(self) -> list[dict[str, Any]]:
        return self._record["mandates"]

    @property
    def ledger(self) -> list[dict[str, Any]]:
        if "ledger" not in self._record:
            raise KataError("agreement has no spend ledger")
        return self._record["ledger"]

    @property
    def parent_limits(self) -> dict[str, Any]:
        return self._record.get("parent_limits") or {}

    @property
    def events(self) -> list[dict[str, Any]]:
        return self._record["events"]

    @property
    def log_head(self) -> str | None:
        if not self.events:
            return None
        return self.events[-1]["event_hash"]

    def rendering_preview(self, intent_id: str | None = None) -> str:
        """The default English text for one live intent."""

        return render_mandate(self._select(intent_id))

    def to_delegation(self, delegation: dict[str, Any] | None = None) -> dict[str, Any]:
        """Place this agreement inside a delegation record.

        A caller-supplied delegation is copied and gains ``intent_agreement``.
        Otherwise the library builds the delegation from the parent limits.
        """

        if delegation is None:
            delegation = _delegation_shell(self)
        else:
            delegation = copy.deepcopy(delegation)
        delegation["intent_agreement"] = self.to_dict()
        return delegation

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
        snapshot = copy.deepcopy(self._record)
        try:
            mandate = self._select(None)
            old_intent = copy.deepcopy(mandate["intent"])
            old_limits = copy.deepcopy(mandate.get("limits"))
            old_expires = mandate.get("expires_at")
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
            parent = _refresh_parent(
                copy.deepcopy(self.parent_limits),
                old_intent,
                mandate["intent"],
                old_limits,
                mandate.get("limits"),
                old_expires,
                mandate.get("expires_at"),
            )
            _assert_subset(
                mandate["intent"],
                mandate.get("limits"),
                parent,
                Decimal(0),
                expires_at=mandate.get("expires_at"),
            )
            mandate["parent_limits"] = parent
            self._record["parent_limits"] = parent
            _check_window_consistency(mandate)
        except KataError:
            self._record = snapshot
            raise
        self._record["status"] = "clarifying"
        self._append_event(
            type="clarified",
            actor=actor,
            at=as_time(at),
            mandate_hash=hash_document(draft_document(mandate)),
            note=note,
        )

    def accept(
        self,
        principal_key: PrivateKey,
        at: str | Any,
        *,
        confirmed_text: str | None = None,
        rendering_text: str | None = None,
    ) -> None:
        """Principal signs the current draft.

        ``rendering_text`` is the confirmation in any language. When it is
        omitted, the default English rendering is signed. ``confirmed_text``,
        when passed, must be that same text.
        """

        self._require_status("proposed", "clarifying")
        mandate = self._select(None)
        mandate["principal"]["public_key"] = principal_key.public.to_jwk()
        try:
            _apply_rendering(mandate, rendering_text=rendering_text, confirmed_text=confirmed_text)
        except KataError:
            mandate["principal"].pop("public_key", None)
            raise
        signed = signing_document(mandate)
        mandate["signature"] = sign_jws(signed, principal_key, typ=MANDATE_TYP)
        stamped = as_time(at)
        self._append_event(
            type="accepted",
            actor=Actor("principal", mandate["principal"]["id"]),
            at=stamped,
            mandate_hash=hash_document(signed),
        )
        if self._required_roles_met(mandate):
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
        intent_id: str | None = None,
    ) -> None:
        """Countersign one live mandate hash. This is the optional counterparty acknowledgement."""

        self._require_status("accepted", "active")
        mandate = self._select(intent_id)
        if role not in ACK_ROLES:
            raise KataError(f"cannot acknowledge as {role}")
        if mandate.get("signature") is None:
            raise KataError("cannot acknowledge an unsigned mandate")
        if role == "agent" and party_id != mandate["agent"]["agent_id"]:
            raise KataError("agent acknowledgement id does not match the bound agent")
        if role == "agent" and private_key.public.fingerprint != mandate["agent"]["public_key_fingerprint"]:
            raise KataError("agent acknowledgement key does not match the bound agent")
        current = mandate_hash(mandate)
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
        if self.status == "accepted" and self._required_roles_met(mandate):
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
        rendering_text: str | None = None,
        intent_id: str | None = None,
        parent_limits: dict[str, Any] | None = None,
    ) -> None:
        """Sign a new version of one live intent. The previous version stays in the history."""

        self._require_status("active")
        self._require_principal_key(principal_key)
        target = self._select(intent_id)
        previous = mandate_hash(target)
        version = int(target["version"]) + 1
        updated = copy.deepcopy(target)
        updated.pop("signature", None)
        updated.pop("rendering", None)
        updated["version"] = version
        updated["supersedes"] = previous
        updated["mandate_id"] = _next_mandate_id(self.agreement_id, updated["intent"]["intent_id"], version, target["mandate_id"])
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
        parent = copy.deepcopy(self.parent_limits)
        if parent_limits is not None:
            parent = _merge_parent(parent, parent_limits)
        others = [item for item in self.mandates if item["intent"]["intent_id"] != updated["intent"]["intent_id"]]
        _assert_subset(
            updated["intent"],
            updated.get("limits"),
            parent,
            _allocated_cumulative(others, parent),
            expires_at=updated.get("expires_at"),
        )
        for other in others:
            _assert_subset(
                other["intent"],
                other.get("limits"),
                parent,
                Decimal(0),
                expires_at=other.get("expires_at"),
            )
        _check_window_consistency(updated)
        updated["parent_limits"] = parent
        updated["principal"]["public_key"] = principal_key.public.to_jwk()
        _apply_rendering(updated, rendering_text=rendering_text, confirmed_text=confirmed_text)
        signed = signing_document(updated)
        updated["signature"] = sign_jws(signed, principal_key, typ=MANDATE_TYP)
        self._record["mandate_history"].append(copy.deepcopy(target))
        index = self.mandates.index(target)
        self.mandates[index] = updated
        self._record["parent_limits"] = parent
        if parent_limits is not None:
            self._resign_siblings(updated, parent, principal_key)
        self._record["acknowledgements"] = [
            ack for ack in self._record["acknowledgements"] if ack.get("mandate_hash") != previous
        ]
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
        if len(self.mandates) == 1:
            if self._required_roles_met(updated):
                self._record["status"] = "active"
            else:
                self._record["status"] = "accepted"

    def add_intent(
        self,
        principal_key: PrivateKey,
        at: str | Any,
        *,
        intent: dict[str, Any],
        limits: dict[str, Any] | None = None,
        not_before: str | None = None,
        expires_at: str | None = None,
        note: str | None = None,
        confirmed_text: str | None = None,
        rendering_text: str | None = None,
    ) -> None:
        """Sign another live intent under this agreement.

        The new intent must be a subset of the parent set. Its per-transaction
        ceiling cannot exceed the parent's, and the sum of the live cumulative
        slices cannot exceed the parent's cumulative total.
        """

        self._require_status("active")
        self._require_principal_key(principal_key)
        intent = _validate_intent(coerce(intent))
        if any(item["intent"]["intent_id"] == intent["intent_id"] for item in self.mandates):
            raise KataError("intent_id is already live on this agreement")
        intent["version"] = 1
        limits = _validate_limits(coerce(limits) if limits else None, intent)
        parent = copy.deepcopy(self.parent_limits)
        chosen_expiry = as_time(expires_at) if expires_at else intent.get("time_limit")
        _assert_subset(intent, limits, parent, _allocated_cumulative(self.mandates, parent), expires_at=chosen_expiry)
        base = self.mandates[0]
        mandate: dict[str, Any] = {
            "agent": copy.deepcopy(base["agent"]),
            "intent": intent,
            "mandate_id": f"{self.agreement_id}.{intent['intent_id']}.v1",
            "parent_limits": parent,
            "principal": copy.deepcopy(base["principal"]),
            "version": 1,
        }
        if base.get("delegation_id"):
            mandate["delegation_id"] = base["delegation_id"]
        if chosen_expiry:
            mandate["expires_at"] = as_time(chosen_expiry)
        if limits:
            mandate["limits"] = limits
        if not_before is not None:
            mandate["not_before"] = as_time(not_before)
        if base.get("required_acknowledgements"):
            mandate["required_acknowledgements"] = list(base["required_acknowledgements"])
        if base.get("revocation_endpoint"):
            mandate["revocation_endpoint"] = base["revocation_endpoint"]
        _check_window_consistency(mandate)
        mandate["principal"]["public_key"] = principal_key.public.to_jwk()
        _apply_rendering(mandate, rendering_text=rendering_text, confirmed_text=confirmed_text)
        signed = signing_document(mandate)
        mandate["signature"] = sign_jws(signed, principal_key, typ=MANDATE_TYP)
        self.mandates.append(mandate)
        self._append_event(
            type="added",
            actor=Actor("principal", mandate["principal"]["id"]),
            at=as_time(at),
            mandate_hash=hash_document(signed),
            note=note,
            detail={"intent_id": intent["intent_id"]},
        )

    def record_allowed(self, action: dict[str, Any], *, at: str | Any | None = None, outcome: str = "allowed", intent_id: str | None = None) -> None:
        """Append a charge to the ledger KATA holds on this agreement."""

        if "ledger" not in self._record:
            raise KataError("agreement has no spend ledger")
        if outcome not in {"allowed", "authorized", "settled", "failed"}:
            raise KataError("ledger outcome is not allowed, authorized, settled, or failed")
        action = coerce(action)
        chosen = intent_id or (action.get("parameters") or {}).get("intent_id")
        if not chosen:
            if len(self.mandates) != 1:
                raise KataError("intent_id is required when several intents are live")
            chosen = self.mandates[0]["intent"]["intent_id"]
        elif not any(item["intent"]["intent_id"] == chosen for item in self.mandates):
            raise KataError(f"no live intent {chosen}")
        entry: dict[str, Any] = {
            "action_id": require_text(action.get("action_id"), "action_id"),
            "at": as_time(at or action.get("proposed_at")),
            "currency": require_text(action.get("currency"), "currency"),
            "intent_id": chosen,
            "outcome": outcome,
        }
        if action.get("amount") is not None:
            entry["amount"] = money(action["amount"])
        idempotency = (action.get("settlement") or {}).get("idempotency_key")
        if idempotency:
            entry["idempotency_key"] = idempotency
        self.ledger.append(entry)

    def revoke(self, principal_key: PrivateKey, at: str | Any, *, reason: str = "principal_request") -> dict[str, Any]:
        """Sign a revocation of every live intent. Only the signing principal's key is accepted."""

        self._require_status("proposed", "clarifying", "accepted", "active")
        if any(item.get("signature") for item in self.mandates):
            self._require_principal_key(principal_key)
        hashes = [
            mandate_hash(item) if item.get("signature") else hash_document(draft_document(item)) for item in self.mandates
        ]
        document: dict[str, Any] = {
            "agreement_id": self.agreement_id,
            "at": as_time(at),
            "kata_revocation": "1",
            "mandate_hash": hashes[0],
            "reason": require_text(reason, "reason"),
        }
        if len(hashes) > 1:
            document["mandate_hashes"] = hashes
        revocation = dict(document)
        revocation["signature"] = sign_jws(document, principal_key, typ=REVOCATION_TYP)
        self._record["revocation"] = revocation
        self._record["status"] = "revoked"
        self._append_event(
            type="revoked",
            actor=Actor("principal", self.mandates[0]["principal"]["id"]),
            at=document["at"],
            mandate_hash=hashes[0],
            detail={"reason": reason},
        )
        return revocation

    def expire(self, at: str | Any) -> None:
        """Record expiry once ``at`` is past every live intent. Evaluation also enforces each window on its own."""

        self._require_status("proposed", "clarifying", "accepted", "active")
        stamped = as_time(at)
        expiries = [_mandate_expiry(item) for item in self.mandates]
        expiries = [item for item in expiries if item]
        if not expiries:
            raise KataError("agreement has no expiry")
        if parse_time(stamped) <= max(parse_time(item) for item in expiries):
            raise KataError("agreement has not expired")
        self._record["status"] = "expired"
        self._append_event(
            type="expired",
            actor=Actor("policy", "expiry"),
            at=stamped,
            mandate_hash=mandate_hash(self.mandates[0]),
        )

    def _select(self, intent_id: str | None) -> dict[str, Any]:
        mandates = self._record["mandates"]
        if intent_id is None:
            if len(mandates) != 1:
                raise KataError("intent_id is required when several intents are live")
            return mandates[0]
        for mandate in mandates:
            if mandate.get("intent", {}).get("intent_id") == intent_id:
                return mandate
        raise KataError(f"no live intent {intent_id}")

    def _resign_siblings(self, updated: dict[str, Any], parent: dict[str, Any], principal_key: PrivateKey) -> None:
        """Re-sign the other live intents so they carry the same parent set."""

        for index, mandate in enumerate(self.mandates):
            if mandate is updated or mandate["intent"]["intent_id"] == updated["intent"]["intent_id"]:
                continue
            resigned = copy.deepcopy(mandate)
            text = (resigned.get("rendering") or {}).get("text")
            resigned.pop("signature", None)
            resigned["parent_limits"] = copy.deepcopy(parent)
            if text:
                resigned["rendering"] = {"hash": text_hash(text), "text": text}
            resigned["signature"] = sign_jws(signing_document(resigned), principal_key, typ=MANDATE_TYP)
            self.mandates[index] = resigned

    def _require_status(self, *allowed: str) -> None:
        if self.status not in allowed:
            raise KataError(f"cannot do that while the agreement is {self.status}")

    def _require_principal_key(self, key: PrivateKey) -> None:
        embedded = None
        for mandate in self.mandates:
            embedded = (mandate.get("principal") or {}).get("public_key")
            if embedded:
                break
        if not embedded:
            raise KataError("mandate has no principal public key")
        if public_key_from_jwk(embedded).fingerprint != key.public.fingerprint:
            raise KataError("principal key does not match the signed mandate")

    def _required_roles_met(self, mandate: dict[str, Any]) -> bool:
        required = set(mandate.get("required_acknowledgements") or [])
        if not required:
            return True
        current = mandate_hash(mandate)
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


def _apply_rendering(mandate: dict[str, Any], *, rendering_text: str | None, confirmed_text: str | None) -> None:
    text = rendering_text if rendering_text is not None else render_mandate(mandate)
    if not isinstance(text, str) or not text.strip():
        raise KataError("rendering text is empty")
    if confirmed_text is not None and confirmed_text != text:
        raise KataError("confirmed text does not match the mandate rendering")
    mandate["rendering"] = {"hash": text_hash(text), "text": text}


def _mandate_expiry(mandate: dict[str, Any]) -> str | None:
    expiry = mandate.get("expires_at") or (mandate.get("intent") or {}).get("time_limit")
    return as_time(expiry) if expiry else None


def _next_mandate_id(agreement_id: str, intent_id: str, version: int, previous_id: str) -> str:
    if previous_id.startswith(f"{agreement_id}.{intent_id}."):
        return f"{agreement_id}.{intent_id}.v{version}"
    return f"{agreement_id}.v{version}"


def _delegation_shell(agreement: Agreement) -> dict[str, Any]:
    mandate = agreement.mandates[0]
    parent = agreement.parent_limits
    intent_ids = [item["intent"]["intent_id"] for item in agreement.mandates]
    status = {"active": "active", "revoked": "revoked", "expired": "expired"}.get(agreement.status, "suspended")
    scope: dict[str, Any] = {
        "allowed_action_verbs": list(parent.get("allowed_actions") or mandate["intent"].get("allowed_actions") or []),
        "intent_ids": intent_ids,
    }
    currency = parent.get("currency") or mandate["intent"].get("currency")
    if currency:
        scope["currency"] = currency
    if parent.get("maximum_amount") is not None:
        scope["maximum_amount"] = parent["maximum_amount"]
    if parent.get("cumulative_maximum") is not None:
        scope["cumulative_maximum"] = parent["cumulative_maximum"]
    expires_at = mandate.get("expires_at") or parent.get("expires_at")
    shell: dict[str, Any] = {
        "agent": {"agent_id": mandate["agent"]["agent_id"]},
        "delegation_id": mandate.get("delegation_id") or agreement.agreement_id,
        "granted_at": agreement.to_dict()["created_at"],
        "principal": {
            key: mandate["principal"][key] for key in ("display_name", "id", "type") if key in mandate["principal"]
        },
        "purpose": mandate["intent"].get("purpose") or "act",
        "revocable": True,
        "scope": scope,
        "status": status,
    }
    if expires_at:
        shell["expires_at"] = expires_at
    return shell


def _initial_parent(
    intent: dict[str, Any],
    limits: dict[str, Any] | None,
    explicit: dict[str, Any] | None,
    expires_at: str | None,
) -> dict[str, Any]:
    parent: dict[str, Any] = {}
    if explicit:
        parent = _merge_parent({}, explicit)
    if intent.get("currency") and "currency" not in parent:
        parent["currency"] = intent["currency"]
    if limits and limits.get("currency") and "currency" not in parent:
        parent["currency"] = limits["currency"]
    if intent.get("maximum_amount") is not None and "maximum_amount" not in parent:
        parent["maximum_amount"] = money(intent["maximum_amount"])
    if limits and limits.get("cumulative_maximum") is not None and "cumulative_maximum" not in parent:
        parent["cumulative_maximum"] = money(limits["cumulative_maximum"])
    for key in ("allowed_actions", "category", "merchant_constraints", "purpose"):
        if key not in parent and key in intent:
            parent[key] = copy.deepcopy(intent[key])
    if "expires_at" not in parent and (expires_at or intent.get("time_limit")):
        parent["expires_at"] = as_time(expires_at or intent["time_limit"])
    _assert_subset(intent, limits, parent, Decimal(0), expires_at=expires_at or intent.get("time_limit"))
    return parent


def _merge_parent(existing: dict[str, Any], explicit: dict[str, Any]) -> dict[str, Any]:
    parent = copy.deepcopy(existing)
    incoming = coerce(explicit)
    if not isinstance(incoming, dict):
        raise KataError("parent_limits must be an object")
    for key, value in incoming.items():
        if key in {"maximum_amount", "cumulative_maximum"}:
            amount = money(value)
            if amount < 0:
                raise KataError(f"parent {key} cannot be negative")
            parent[key] = amount
        elif key == "expires_at":
            parent[key] = as_time(value)
        else:
            parent[key] = value
    return parent


def _refresh_parent(
    parent: dict[str, Any],
    old_intent: dict[str, Any],
    new_intent: dict[str, Any],
    old_limits: dict[str, Any] | None,
    new_limits: dict[str, Any] | None,
    old_expires: str | None,
    new_expires: str | None,
) -> dict[str, Any]:
    """Keep a draft parent aligned with the only intent when the parent was mirroring it."""

    _mirror(parent, "maximum_amount", old_intent.get("maximum_amount"), new_intent.get("maximum_amount"), money_value=True)
    old_total = (old_limits or {}).get("cumulative_maximum")
    new_total = (new_limits or {}).get("cumulative_maximum")
    _mirror(parent, "cumulative_maximum", old_total, new_total, money_value=True)
    _mirror(parent, "currency", old_intent.get("currency"), new_intent.get("currency"))
    for key in ("allowed_actions", "category", "merchant_constraints", "purpose"):
        _mirror(parent, key, old_intent.get(key), new_intent.get(key))
    _mirror(parent, "expires_at", old_expires or old_intent.get("time_limit"), new_expires or new_intent.get("time_limit"))
    return parent


def _mirror(parent: dict[str, Any], key: str, old: Any, new: Any, *, money_value: bool = False) -> None:
    current = parent.get(key)
    if money_value:
        same = _money_same(current, old)
        if same:
            if new is None:
                parent.pop(key, None)
            else:
                parent[key] = money(new)
        return
    if current == old or (old is None and key not in parent):
        if new is None:
            parent.pop(key, None)
        else:
            parent[key] = copy.deepcopy(new)


def _money_same(left: Any, right: Any) -> bool:
    if left is None or right is None:
        return left is None and right is None
    return money(left) == money(right)


def _allocated_cumulative(mandates: list[dict[str, Any]], parent: dict[str, Any]) -> Decimal:
    total = Decimal(0)
    parent_total = parent.get("cumulative_maximum")
    for mandate in mandates:
        value = (mandate.get("limits") or {}).get("cumulative_maximum")
        if value is None:
            if parent_total is None:
                continue
            total += money(parent_total)
        else:
            total += money(value)
    return total


def _assert_subset(
    intent: dict[str, Any],
    limits: dict[str, Any] | None,
    parent: dict[str, Any],
    siblings_cumulative: Decimal,
    *,
    expires_at: str | None = None,
) -> None:
    """Reject an intent that is wider than the parent set."""

    if parent.get("currency") and intent.get("currency") and intent["currency"] != parent["currency"]:
        raise KataError("intent currency is outside the parent set")
    if parent.get("purpose") and intent.get("purpose") and intent["purpose"] != parent["purpose"]:
        raise KataError("intent purpose is outside the parent set")
    if parent.get("category") and intent.get("category") != parent["category"]:
        raise KataError("intent category is outside the parent set")
    if parent.get("maximum_amount") is not None:
        if intent.get("maximum_amount") is None or money(intent["maximum_amount"]) > money(parent["maximum_amount"]):
            raise KataError("intent maximum_amount exceeds the parent set")
    if parent.get("cumulative_maximum") is not None:
        child = None if not limits else limits.get("cumulative_maximum")
        if child is None or money(child) > money(parent["cumulative_maximum"]):
            raise KataError("intent cumulative slice exceeds the parent set")
        if siblings_cumulative + money(child) > money(parent["cumulative_maximum"]):
            raise KataError("the sum of intent cumulative slices exceeds the parent set")
    actions = parent.get("allowed_actions")
    if isinstance(actions, list):
        child_actions = intent.get("allowed_actions")
        if not isinstance(child_actions, list) or not set(child_actions) <= set(actions):
            raise KataError("intent allowed_actions exceed the parent set")
    merchants = parent.get("merchant_constraints")
    if isinstance(merchants, list) and merchants:
        child_merchants = intent.get("merchant_constraints")
        if not isinstance(child_merchants, list) or not child_merchants or not set(child_merchants) <= set(merchants):
            raise KataError("intent merchants exceed the parent set")
    expiry = expires_at or intent.get("time_limit")
    if parent.get("expires_at") and expiry and parse_time(str(expiry)) > parse_time(str(parent["expires_at"])):
        raise KataError("intent expiry exceeds the parent set")


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
