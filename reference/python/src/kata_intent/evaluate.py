# Copyright 2026 Kaan Uluer
# SPDX-License-Identifier: Apache-2.0
"""Compare a proposed action with a signed intent.

The verdict is ``ALLOW``, ``STEP_UP``, or ``DENY``. ``DENY`` maps to the KATA
decision ``BLOCK``. This layer does not emit ``REVOKE``, ``QUARANTINE``, or a
risk score: those belong to the wider decision, and a bad charge does not by
itself revoke a good grant.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any, Mapping, Sequence

from kata_intent.agreement import (
    MANDATE_TYP,
    Agreement,
    verify_event_chain,
    verify_ledger_chain,
    verify_revocation,
)
from kata_intent.canonical import canonical_bytes
from kata_intent.document import acknowledgement_document, mandate_hash, signing_document
from kata_intent.errors import KataError
from kata_intent.jws import same_bytes, verify_jws
from kata_intent.fx import FxRateSource, convert_amount
from kata_intent.institutions import InstitutionDirectory
from kata_intent.keys import PublicKey, public_key_from_jwk
from kata_intent.render import render_mandate
from kata_intent.revocation import (
    RevocationCache,
    TransparencyLog,
    verify_revocation_push,
    verify_tree_head,
)
from kata_intent.values import MONEY_PURPOSES, as_time, coerce, money, parse_time, text_hash

MONEY_ACTIONS = MONEY_PURPOSES
_RISK_RANK = {"low": 0, "medium": 1, "high": 2}
_COUNTING = frozenset({"allowed", "authorized", "settled"})
_APPEALABLE = frozenset(
    {
        "ACTION_EXCEEDS_INTENT",
        "ACTION_NOT_ALLOWED",
        "AMOUNT_ABOVE_INTENT_CEILING",
        "CATEGORY_MISMATCH",
        "CONSTRAINT_VIOLATED",
        "COUNTERPARTY_NOT_ALLOWED",
        "COUNTERPARTY_RISK_EXCEEDED",
        "CUMULATIVE_LIMIT_EXCEEDED",
        "DELEGATION_SCOPE_MISMATCH",
        "FREQUENCY_LIMIT_EXCEEDED",
        "MERCHANT_NOT_ALLOWED",
        "NO_MATCHING_INTENT",
    }
)


@dataclass(frozen=True)
class Policy:
    """Knobs for the intent check. Defaults fail closed on missing money limits and missing time bounds."""

    require_time_limit: bool = True
    require_amount_for_money: bool = True
    require_allowed_actions: bool = True
    clock_skew_seconds: int = 120
    # Off by default. When set, it is a ceiling in reference_currency for an intent with no merchant and no category.
    unscoped_amount_ceiling: Decimal | None = None
    reference_currency: str = "USD"
    fx_rates: FxRateSource | None = None
    max_ledger_staleness_seconds: int = 60


@dataclass(frozen=True)
class LedgerEntry:
    """One earlier charge under the same agreement. KATA stores these on the agreement."""

    action_id: str
    amount: Decimal
    currency: str
    at: datetime
    idempotency_key: str | None = None
    intent_id: str | None = None
    outcome: str = "allowed"

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> LedgerEntry:
        amount = raw.get("amount")
        return cls(
            action_id=str(raw["action_id"]),
            amount=money(amount) if amount is not None else Decimal(0),
            currency=str(raw["currency"]),
            at=parse_time(str(raw["at"])),
            idempotency_key=raw.get("idempotency_key"),
            intent_id=raw.get("intent_id"),
            outcome=str(raw.get("outcome") or "allowed"),
        )


@dataclass(frozen=True)
class Evaluation:
    """Result of checking one action against one mandate."""

    verdict: str
    reasons: tuple[str, ...]
    messages: tuple[str, ...]
    kata_decision: str
    required_action: str
    mandate_hash: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "kata_decision": self.kata_decision,
            "mandate_hash": self.mandate_hash,
            "messages": list(self.messages),
            "reasons": list(self.reasons),
            "required_action": self.required_action,
            "verdict": self.verdict,
        }


@dataclass
class _Findings:
    denies: list[tuple[str, str]] = field(default_factory=list)
    steps: list[tuple[str, str]] = field(default_factory=list)
    _deny_codes: set[str] = field(default_factory=set)
    _step_codes: set[str] = field(default_factory=set)

    def deny(self, code: str, message: str) -> None:
        if code not in self._deny_codes:
            self._deny_codes.add(code)
            self.denies.append((code, message))

    def step(self, code: str, message: str) -> None:
        if code not in self._step_codes:
            self._step_codes.add(code)
            self.steps.append((code, message))


def evaluate(
    subject: Agreement | Mapping[str, Any],
    action: Mapping[str, Any],
    *,
    principal_public_key: PublicKey | None = None,
    agent_id: str | None = None,
    agent_public_key: PublicKey | None = None,
    ledger: Sequence[LedgerEntry | Mapping[str, Any]] | None = None,
    now: str | datetime | None = None,
    seen_action_ids: set[str] | None = None,
    asserted_intent: Mapping[str, Any] | None = None,
    delegation: Mapping[str, Any] | None = None,
    extra_revocations: Sequence[Mapping[str, Any]] | None = None,
    expected_log_head: str | None = None,
    revocation_checked: bool = False,
    policy: Policy | None = None,
    intent_id: str | None = None,
    ledger_head: str | None = None,
    ledger_sequence: int | None = None,
    ledger_as_of: str | datetime | None = None,
    revocation_cache: RevocationCache | None = None,
    revocation_pushes: Sequence[Mapping[str, Any]] | None = None,
    push_notifier_key: PublicKey | None = None,
    transparency_log: TransparencyLog | None = None,
    tree_head: Mapping[str, Any] | None = None,
    tree_head_key: PublicKey | None = None,
    institution_directory: InstitutionDirectory | None = None,
) -> Evaluation:
    """Evaluate ``action`` against a signed mandate, an agreement, or a delegation that holds one.

    The spend ledger is the agreement's ``ledger``. Omit ``ledger`` to use
    that record. An empty list means nothing has been spent. A cumulative or
    frequency limit with no ledger at all is ``DENY``. Pass a list only to
    substitute a ledger for this check. ``extra_revocations`` are signed
    revocations from a log the verifier trusts. Absence of a revocation in
    the agent-presented record is not treated as proof the grant is live.
    """

    policy = policy or Policy()
    raw = subject.to_dict() if isinstance(subject, Agreement) else coerce(dict(subject))
    if isinstance(raw.get("intent_agreement"), dict):
        if delegation is None:
            delegation = raw
        raw = coerce(dict(raw["intent_agreement"]))
    if "agreement_id" in raw and "mandates" not in raw and isinstance(raw.get("mandate"), dict):
        raw = dict(raw)
        raw["mandates"] = [raw.pop("mandate")]

    action_data = coerce(dict(action))
    parameters = action_data.get("parameters") or {}
    if ledger_sequence is None and parameters.get("ledger_sequence") is not None:
        ledger_sequence = int(parameters["ledger_sequence"])
    if ledger_head is None and "ledger_head" in parameters:
        ledger_head = parameters.get("ledger_head")
    if "agreement_id" in raw and isinstance(raw.get("mandates"), list):
        agreement: dict[str, Any] | None = raw
        selected = _select_mandate(raw["mandates"], intent_id, action_data)
        if isinstance(selected, Evaluation):
            return selected
        mandate = selected
    elif "mandate_id" in raw and "intent" in raw:
        agreement = None
        mandate = raw
    else:
        return _result("DENY", [("AGREEMENT_MALFORMED", "The object is neither a mandate nor an agreement.")], None)

    if ledger is None and agreement is not None and "ledger" in agreement:
        ledger = agreement["ledger"]
    findings = _Findings()
    verified_hash: str | None = None

    failure, public_key = _verify_signature(mandate, principal_public_key)
    if failure == "PRINCIPAL_KEY_MISMATCH":
        return _result(
            "DENY",
            [("PRINCIPAL_KEY_MISMATCH", "The principal key does not match the key that signed the mandate.")],
            None,
        )
    if failure:
        code = "MANDATE_TAMPERED" if failure == "MANDATE_TAMPERED" else "MANDATE_SIGNATURE_INVALID"
        message = (
            "The mandate bytes do not match the signature."
            if code == "MANDATE_TAMPERED"
            else "The mandate signature does not verify."
        )
        if not mandate.get("signature") and (agreement or {}).get("status") in {"proposed", "clarifying", "accepted", None}:
            code = "MANDATE_NOT_ACTIVE"
            message = "The principal has not signed this agreement."
        return _result("DENY", [(code, message)], None)

    if principal_public_key is None:
        findings.step(
            "PRINCIPAL_KEY_UNBOUND",
            "The signature matches the embedded key, and no expected principal key was provided.",
        )

    try:
        verified_hash = mandate_hash(mandate)
    except KataError:
        return _result("DENY", [("MANDATE_TAMPERED", "The mandate could not be hashed.")], None)

    _check_rendering(mandate, findings)
    _check_algorithm(mandate, public_key, findings)
    _check_agent_document(mandate, findings)
    try:
        now_dt = _now(now)
        proposed_at = parse_time(action_data["proposed_at"]) if action_data.get("proposed_at") else None
    except (KataError, TypeError):
        findings.deny("ACTION_MALFORMED", "The action timestamp is missing or not timezone-aware.")
        now_dt = datetime.now(timezone.utc)
        proposed_at = None

    gathered, push_failed, head_failed = _gather_revocations(
        extra_revocations,
        revocation_cache,
        revocation_pushes,
        push_notifier_key,
        transparency_log,
        tree_head,
        tree_head_key,
        now_dt,
        findings,
    )
    if revocation_cache is not None or (transparency_log is not None and tree_head is not None and not head_failed):
        revocation_checked = True

    if agreement is not None:
        _check_log(agreement, mandate, findings, expected_log_head, now_dt)
        _check_revocations(agreement, mandate, public_key, gathered, verified_hash, findings)
        _check_acknowledgements(agreement, mandate, verified_hash, findings, institution_directory, now_dt)
    elif gathered and public_key is not None:
        _check_external_revocations(gathered, public_key, None, verified_hash, findings)
    if push_failed:
        findings.deny("REVOCATION_PUSH_INVALID", "A revocation webhook did not verify.")
    _check_family(agreement, mandate, findings)

    if mandate.get("revocation_endpoint") and not revocation_checked and "MANDATE_REVOKED" not in findings._deny_codes:
        findings.step(
            "REVOCATION_ENDPOINT_UNCHECKED",
            "The mandate names a revocation endpoint and the verifier has not checked it.",
        )

    if not action_data.get("action_id") or not action_data.get("action_type") or proposed_at is None:
        findings.deny("ACTION_MALFORMED", "The action is missing action_id, action_type, or a timestamp.")

    if proposed_at is not None:
        _check_time(mandate, action_data, proposed_at, now_dt, policy, findings)
    _check_scope(mandate, action_data, findings)
    _check_price(mandate, action_data, findings)
    _check_counterparty(mandate, action_data, findings)
    _check_constraints(mandate, action_data, findings)
    _check_asserted(mandate, action_data, asserted_intent, findings)
    named_hash = (action_data.get("parameters") or {}).get("mandate_hash")
    if isinstance(named_hash, str) and verified_hash and named_hash != verified_hash:
        findings.deny(
            "MANDATE_SUPERSEDED",
            "The action names a mandate hash that is not the current signed mandate.",
        )
    _check_binding(mandate, agent_id, agent_public_key, findings)
    _check_delegation(mandate, action_data, delegation, proposed_at, now_dt, findings)
    _check_ledger(
        mandate,
        action_data,
        ledger,
        proposed_at,
        seen_action_ids,
        findings,
        agreement,
        ledger_head,
        ledger_sequence,
        ledger_as_of,
        now_dt,
        policy,
    )
    _check_replay_flags(action_data, findings)
    _check_over_broad(mandate, policy, findings, now_dt)

    return _finish(findings, verified_hash)


def _verify_signature(
    mandate: Mapping[str, Any], caller_key: PublicKey | None
) -> tuple[str | None, PublicKey | None]:
    signature = mandate.get("signature")
    jwk = (mandate.get("principal") or {}).get("public_key")
    if not isinstance(signature, dict) or not isinstance(jwk, dict):
        return "MANDATE_SIGNATURE_INVALID", None
    try:
        public = public_key_from_jwk(dict(jwk))
    except KataError:
        return "MANDATE_SIGNATURE_INVALID", None
    if caller_key is not None and caller_key.fingerprint != public.fingerprint:
        return "PRINCIPAL_KEY_MISMATCH", public
    check = verify_jws(signature, public, typ=MANDATE_TYP)
    if not check.ok or check.payload_bytes is None:
        return "MANDATE_SIGNATURE_INVALID", public
    try:
        rebuilt = canonical_bytes(signing_document(dict(mandate)))
    except KataError:
        return "MANDATE_TAMPERED", public
    if not same_bytes(rebuilt, check.payload_bytes):
        return "MANDATE_TAMPERED", public
    if mandate.get("algorithm") != public.algorithm:
        return "MANDATE_SIGNATURE_INVALID", public
    return None, public


def _select_mandate(
    mandates: list[Any], intent_id: str | None, action: Mapping[str, Any]
) -> dict[str, Any] | Evaluation:
    live = [item for item in mandates if isinstance(item, dict)]
    if not live:
        return _result("DENY", [("AGREEMENT_MALFORMED", "The agreement has no live intent.")], None)
    chosen = intent_id or (action.get("parameters") or {}).get("intent_id")
    if chosen is not None:
        for mandate in live:
            if (mandate.get("intent") or {}).get("intent_id") == chosen:
                return mandate
        return _result("DENY", [("INTENT_UNKNOWN", f"No live intent has id {chosen}.")], None)
    if len(live) == 1:
        return live[0]
    matches = [mandate for mandate in live if _intent_matches(mandate, action)]
    if len(matches) == 1:
        return matches[0]
    if not matches:
        return _result(
            "DENY",
            [("NO_MATCHING_INTENT", "No live intent matches this action.")],
            None,
        )
    for mandate in matches:
        failure, _public = _verify_signature(mandate, None)
        if failure:
            code = "MANDATE_TAMPERED" if failure == "MANDATE_TAMPERED" else "MANDATE_SIGNATURE_INVALID"
            return _result("DENY", [(code, "A matching mandate does not verify, so an intent cannot be selected.")], None)
    return _result(
        "STEP_UP",
        [("INTENT_NOT_SELECTED", "More than one live intent matches this action.")],
        None,
    )


def _intent_matches(mandate: Mapping[str, Any], action: Mapping[str, Any]) -> bool:
    """True when this intent could authorize the action's verb, amount, currency, merchant, and category."""

    intent = mandate.get("intent") or {}
    limits = mandate.get("limits") or {}
    action_type = action.get("action_type")
    allowed = intent.get("allowed_actions")
    if isinstance(allowed, list) and action_type not in allowed:
        return False
    if action.get("amount") is not None and intent.get("maximum_amount") is not None:
        try:
            if money(action["amount"]) > money(intent["maximum_amount"]):
                return False
        except KataError:
            return False
    if intent.get("currency") and action.get("currency") and intent["currency"] != action["currency"]:
        return False
    identifiers = _merchant_identifiers(action)
    allow = intent.get("merchant_constraints") or []
    deny = limits.get("merchant_denylist") or []
    if isinstance(deny, list) and deny and any(identifier in deny for identifier in identifiers):
        return False
    if isinstance(allow, list) and allow and not any(identifier in allow for identifier in identifiers):
        return False
    category = intent.get("category")
    observed = (action.get("context") or {}).get("category") or (action.get("parameters") or {}).get("category")
    if category and observed and observed != category:
        return False
    return True


def _check_rendering(mandate: Mapping[str, Any], findings: _Findings) -> None:
    rendering = mandate.get("rendering") or {}
    try:
        produced = render_mandate(dict(mandate))
    except KataError:
        findings.deny("RENDERING_MISMATCH", "KATA could not produce the confirmation text.")
        return
    produced_hash = text_hash(produced)
    text = rendering.get("text")
    if text != produced or rendering.get("hash") != produced_hash:
        findings.deny(
            "RENDERING_MISMATCH",
            "The signed confirmation hash does not equal the hash of the text KATA produced.",
        )


def _check_algorithm(mandate: Mapping[str, Any], public_key: PublicKey | None, findings: _Findings) -> None:
    algorithm = mandate.get("algorithm")
    if algorithm not in {"EdDSA", "ES256"}:
        findings.deny("MANDATE_SIGNATURE_INVALID", "The mandate does not name EdDSA or ES256.")
        return
    if public_key is not None and public_key.algorithm != algorithm:
        findings.deny("MANDATE_SIGNATURE_INVALID", "The mandate algorithm does not match the signing key.")


def _check_agent_document(mandate: Mapping[str, Any], findings: _Findings) -> None:
    agent = mandate.get("agent") or {}
    embedded = agent.get("public_key")
    fingerprint = agent.get("public_key_fingerprint")
    if not isinstance(embedded, dict) or not isinstance(fingerprint, str):
        findings.deny("AGENT_BINDING_MISMATCH", "The mandate does not bind an agent key.")
        return
    try:
        key = public_key_from_jwk(dict(embedded))
    except KataError:
        findings.deny("AGENT_BINDING_MISMATCH", "The embedded agent key is not an Ed25519 or P-256 public key.")
        return
    if key.fingerprint != fingerprint:
        findings.deny("AGENT_BINDING_MISMATCH", "The agent key fingerprint does not match the embedded key.")


def _check_log(
    agreement: Mapping[str, Any],
    mandate: Mapping[str, Any],
    findings: _Findings,
    expected_log_head: str | None,
    now: datetime,
) -> None:
    events = agreement.get("events")
    if not isinstance(events, list) or not verify_event_chain(list(events)):
        findings.deny("AGREEMENT_LOG_TAMPERED", "The agreement event log does not hash to itself.")
        return
    if expected_log_head is not None:
        head = events[-1]["event_hash"] if events else None
        if head != expected_log_head:
            findings.deny(
                "AGREEMENT_LOG_TAMPERED",
                "The agreement log head does not match the head the verifier has seen.",
            )
    status = agreement.get("status")
    if status == "revoked" and "revocation" not in agreement:
        findings.deny("AGREEMENT_LOG_TAMPERED", "The agreement says revoked and carries no signed revocation.")
    expires_at = mandate.get("expires_at") or (mandate.get("intent") or {}).get("time_limit")
    if status == "expired" and expires_at:
        try:
            if now <= parse_time(str(expires_at)):
                findings.deny(
                    "AGREEMENT_LOG_TAMPERED",
                    "The agreement says expired before its signed expiry.",
                )
        except KataError:
            findings.deny("AGREEMENT_LOG_TAMPERED", "The agreement expiry could not be read.")


def _check_revocations(
    agreement: Mapping[str, Any],
    mandate: Mapping[str, Any],
    public_key: PublicKey | None,
    extra: Sequence[Mapping[str, Any]] | None,
    current_hash: str | None,
    findings: _Findings,
) -> None:
    if public_key is None or current_hash is None:
        return
    embedded = agreement.get("revocation")
    if isinstance(embedded, dict):
        if _revocation_matches(embedded, public_key, agreement.get("agreement_id"), current_hash):
            findings.deny("MANDATE_REVOKED", "The principal revoked this mandate.")
        else:
            findings.deny("AGREEMENT_LOG_TAMPERED", "The embedded revocation does not verify.")
    if agreement.get("status") == "revoked" and "MANDATE_REVOKED" not in findings._deny_codes:
        findings.deny("AGREEMENT_LOG_TAMPERED", "The agreement is marked revoked without a valid revocation signature.")
    _check_external_revocations(extra, public_key, agreement.get("agreement_id"), current_hash, findings)


def _check_external_revocations(
    extra: Sequence[Mapping[str, Any]] | None,
    public_key: PublicKey,
    agreement_id: str | None,
    current_hash: str | None,
    findings: _Findings,
) -> None:
    for revocation in extra or []:
        if _revocation_matches(revocation, public_key, agreement_id, current_hash):
            findings.deny("MANDATE_REVOKED", "A trusted revocation log says the principal revoked this mandate.")


def _revocation_matches(
    revocation: Mapping[str, Any],
    public_key: PublicKey,
    agreement_id: str | None,
    current_hash: str | None,
) -> bool:
    if not verify_revocation(dict(revocation), public_key):
        return False
    if agreement_id is not None and revocation.get("agreement_id") != agreement_id:
        return False
    hashes = revocation.get("mandate_hashes")
    if isinstance(hashes, list) and current_hash in hashes:
        return True
    return revocation.get("mandate_hash") == current_hash


def _gather_revocations(
    extra: Sequence[Mapping[str, Any]] | None,
    cache: RevocationCache | None,
    pushes: Sequence[Mapping[str, Any]] | None,
    notifier: PublicKey | None,
    log: TransparencyLog | None,
    tree_head: Mapping[str, Any] | None,
    tree_head_key: PublicKey | None,
    now: datetime,
    findings: _Findings,
) -> tuple[list[dict[str, Any]], bool, bool]:
    gathered = [dict(item) for item in extra or [] if isinstance(item, Mapping)]
    push_failed = False
    head_failed = False
    if cache is not None:
        try:
            gathered.extend(cache.get(now))
        except KataError:
            findings.deny("REVOCATION_LIST_UNAVAILABLE", "The revocation list could not be pulled.")
    if pushes:
        if notifier is None:
            push_failed = True
        else:
            for notice in pushes:
                inner = verify_revocation_push(notice, notifier)
                if inner is None:
                    push_failed = True
                else:
                    gathered.append(inner)
    if log is not None or tree_head is not None:
        if log is None or tree_head is None or tree_head_key is None or not verify_tree_head(tree_head, tree_head_key, log):
            head_failed = True
            findings.deny("TREE_HEAD_INVALID", "The transparency log tree head does not verify.")
        elif not log.verify_chain():
            findings.deny("TRANSPARENCY_LOG_TAMPERED", "The transparency log hash chain does not verify.")
        else:
            gathered.extend(log.revocations())
    return gathered, push_failed, head_failed


def _check_acknowledgements(
    agreement: Mapping[str, Any],
    mandate: Mapping[str, Any],
    current_hash: str | None,
    findings: _Findings,
    directory: InstitutionDirectory | None = None,
    now: datetime | None = None,
) -> None:
    required = set(mandate.get("required_acknowledgements") or [])
    satisfied: set[str] = set()
    agent_fingerprint = (mandate.get("agent") or {}).get("public_key_fingerprint")
    for ack in agreement.get("acknowledgements") or []:
        if not isinstance(ack, dict) or ack.get("mandate_hash") != current_hash:
            continue
        try:
            key = public_key_from_jwk(dict(ack.get("public_key") or {}))
            check = verify_jws(ack.get("signature") or {}, key, typ="kata-ack+jws")
            matches = (
                check.ok
                and check.payload_bytes is not None
                and same_bytes(check.payload_bytes, canonical_bytes(acknowledgement_document(dict(ack))))
            )
        except KataError:
            matches = False
            key = None
        if not matches:
            findings.deny("ACK_SIGNATURE_INVALID", "A counterparty acknowledgement does not verify.")
            continue
        if ack.get("role") == "agent" and (key is None or key.fingerprint != agent_fingerprint):
            findings.deny("ACK_KEY_MISMATCH", "The agent acknowledgement was signed by a different key.")
            continue
        role = ack.get("role")
        if role in {"merchant", "psp", "issuer"} and directory is not None and key is not None and now is not None:
            domain = ack.get("domain") if isinstance(ack.get("domain"), str) else None
            if not directory.trusts(str(ack.get("id") or ""), key, now, domain):
                findings.deny(
                    "INSTITUTION_KEY_UNTRUSTED",
                    "The institution key is not in the KATA allowlist or the domain's published keys.",
                )
                continue
        role = ack.get("role")
        if isinstance(role, str):
            satisfied.add(role)
    missing = required - satisfied
    if missing:
        findings.step(
            "COUNTERPARTY_ACK_REQUIRED",
            "The mandate still needs an acknowledgement from: " + ", ".join(sorted(missing)) + ".",
        )


def _check_time(
    mandate: Mapping[str, Any],
    action: Mapping[str, Any],
    proposed_at: datetime,
    now: datetime,
    policy: Policy,
    findings: _Findings,
) -> None:
    skew = timedelta(seconds=policy.clock_skew_seconds)
    if proposed_at > now + skew:
        findings.deny("ACTION_TIME_IN_FUTURE", "The action timestamp is ahead of the verifier's clock.")
    intent = mandate.get("intent") or {}
    expires_at = mandate.get("expires_at")
    time_limit = intent.get("time_limit")
    if expires_at and time_limit and as_time(str(expires_at)) != as_time(str(time_limit)):
        findings.deny("WINDOW_INCONSISTENT", "expires_at and intent.time_limit disagree.")
    expiry_text = expires_at or time_limit
    if expiry_text:
        expiry = parse_time(str(expiry_text))
        if proposed_at > expiry or now > expiry:
            findings.deny("MANDATE_EXPIRED", "The mandate expired before this action.")
    not_before = mandate.get("not_before")
    if not_before and proposed_at < parse_time(str(not_before)):
        findings.deny("MANDATE_NOT_YET_VALID", "The action is before the mandate's not_before time.")


def _check_scope(mandate: Mapping[str, Any], action: Mapping[str, Any], findings: _Findings) -> None:
    intent = mandate.get("intent") or {}
    limits = mandate.get("limits") or {}
    action_type = action.get("action_type")
    allowed = intent.get("allowed_actions")
    if isinstance(allowed, list) and action_type not in allowed:
        findings.deny("ACTION_NOT_ALLOWED", f"The action {action_type} is not in the signed allowed actions.")
        findings.deny("ACTION_EXCEEDS_INTENT", "The action is outside the signed intent.")

    ceiling = intent.get("maximum_amount")
    restated = limits.get("per_transaction_maximum")
    if ceiling is not None and restated is not None and money(ceiling) != money(restated):
        findings.deny("LIMIT_INCONSISTENT", "The per-transaction limit does not match intent.maximum_amount.")
    if limits.get("currency") and intent.get("currency") and limits["currency"] != intent["currency"]:
        findings.deny("LIMIT_INCONSISTENT", "The limits currency does not match the intent currency.")

    amount = action.get("amount")
    if amount is not None:
        parsed = money(amount)
        if parsed < 0:
            findings.deny("ACTION_MALFORMED", "The action amount is negative.")
        elif ceiling is not None and parsed > money(ceiling):
            findings.deny(
                "AMOUNT_ABOVE_INTENT_CEILING",
                f"Amount {_plain(parsed)} {action.get('currency', '')} exceeds the intent ceiling of {_plain(money(ceiling))} {intent.get('currency', '')}.",
            )
            findings.deny("ACTION_EXCEEDS_INTENT", "The action is outside the signed intent.")
        action_currency = action.get("currency")
        intent_currency = intent.get("currency")
        if intent_currency and action_currency != intent_currency:
            findings.deny("CURRENCY_MISMATCH", "The action currency does not match the intent currency.")

    if action_type in MONEY_ACTIONS and amount is None:
        findings.step("AMOUNT_NOT_PROVIDED", "This money action has no amount.")

    category = intent.get("category")
    observed = (action.get("context") or {}).get("category") or (action.get("parameters") or {}).get("category")
    if category and observed and observed != category:
        findings.deny("CATEGORY_MISMATCH", f"The action category {observed} is not {category}.")

    identifiers = _merchant_identifiers(action)
    allow = intent.get("merchant_constraints") or []
    deny = limits.get("merchant_denylist") or []
    if not isinstance(allow, list) or not isinstance(deny, list):
        findings.deny("LIMIT_INCONSISTENT", "Merchant constraints are not lists.")
    else:
        if deny and any(identifier in deny for identifier in identifiers):
            findings.deny("MERCHANT_NOT_ALLOWED", "The merchant is on the signed denylist.")
        if allow and not any(identifier in allow for identifier in identifiers):
            findings.deny("MERCHANT_NOT_ALLOWED", "The merchant is not on the signed allowlist.")


def _check_price(mandate: Mapping[str, Any], action: Mapping[str, Any], findings: _Findings) -> None:
    intent = mandate.get("intent") or {}
    expectation = intent.get("price_expectation") or {}
    if not expectation:
        _check_fees(intent, action, findings)
        return
    price = action.get("price") or {}
    charged = price.get("charged_amount", action.get("amount"))
    references: list[tuple[str, Any]] = []
    if expectation.get("quoted_price") is not None:
        references.append(("CHARGE_EXCEEDS_QUOTE", expectation["quoted_price"]))
    if expectation.get("listed_price") is not None:
        references.append(("CHARGE_EXCEEDS_LISTED", expectation["listed_price"]))
    if price.get("quoted_price") is not None:
        references.append(("CHARGE_EXCEEDS_QUOTE", price["quoted_price"]))
    if price.get("listed_price") is not None:
        references.append(("CHARGE_EXCEEDS_LISTED", price["listed_price"]))
    tolerance = expectation.get("tolerance_ratio")
    if charged is None and references:
        findings.step("AMOUNT_NOT_PROVIDED", "A price expectation is signed and the action has no charge.")
    elif references and tolerance is None:
        findings.step(
            "TOLERANCE_NOT_DECLARED",
            "A quote or list price is signed and no tolerance band was declared.",
        )
    elif charged is not None and tolerance is not None:
        band = money(tolerance)
        if band <= 0:
            findings.deny("LIMIT_INCONSISTENT", "The price tolerance must be greater than zero.")
        else:
            charged_amount = money(charged)
            for code, reference in references:
                if charged_amount > money(reference) * band:
                    findings.deny(code, f"The charge {_plain(charged_amount)} is outside the signed price band.")
    _check_fees(intent, action, findings)


def _check_fees(intent: Mapping[str, Any], action: Mapping[str, Any], findings: _Findings) -> None:
    fee_policy = intent.get("fee_policy") or {}
    breakdown = (action.get("price") or {}).get("fee_breakdown") or []
    if not fee_policy or not breakdown:
        return
    allowed = fee_policy.get("allowed_codes")
    allow_undisclosed = bool(fee_policy.get("allow_undisclosed"))
    for line in breakdown:
        if not isinstance(line, dict) or line.get("code") == "item":
            continue
        if isinstance(allowed, list) and line.get("code") not in allowed:
            findings.deny("FEE_NOT_ACCEPTED", f"The fee {line.get('code')} is not in the signed fee policy.")
        if line.get("disclosed") is not True and not allow_undisclosed:
            findings.deny("UNDISCLOSED_FEE", "The charge includes a fee that was not disclosed.")


def _check_counterparty(mandate: Mapping[str, Any], action: Mapping[str, Any], findings: _Findings) -> None:
    constraints = (mandate.get("intent") or {}).get("counterparty_constraints") or {}
    counterparty = action.get("counterparty") or {}
    allowed_ids = constraints.get("allowed_merchant_ids") or []
    if allowed_ids:
        merchant_id = counterparty.get("merchant_id")
        if merchant_id not in allowed_ids:
            findings.deny("COUNTERPARTY_NOT_ALLOWED", "The merchant id is not in the signed counterparty list.")
    allowed_payees = constraints.get("allowed_settlement_addresses") or []
    if allowed_payees and counterparty.get("settlement_address") not in allowed_payees:
        findings.deny("COUNTERPARTY_NOT_ALLOWED", "The settlement address is not in the signed payee list.")
    settlement = counterparty.get("settlement_address")
    registered = counterparty.get("registered_settlement_address")
    if settlement and registered and settlement != registered:
        findings.deny(
            "SETTLEMENT_ADDRESS_MISMATCH",
            "The settlement address does not match the address registered for this merchant.",
        )
    maximum = constraints.get("maximum_risk")
    if maximum in _RISK_RANK:
        observed = (counterparty.get("reputation") or {}).get("risk")
        if observed in _RISK_RANK and _RISK_RANK[observed] > _RISK_RANK[maximum]:
            findings.deny("COUNTERPARTY_RISK_EXCEEDED", "The counterparty risk is above the signed maximum.")
        elif observed not in _RISK_RANK:
            findings.step("COUNTERPARTY_RISK_UNKNOWN", "The mandate caps counterparty risk and this action has no known risk.")


def _check_constraints(mandate: Mapping[str, Any], action: Mapping[str, Any], findings: _Findings) -> None:
    constraints = (mandate.get("intent") or {}).get("constraints") or {}
    max_items = constraints.get("max_items")
    quantity = (action.get("parameters") or {}).get("quantity")
    if max_items is None or quantity is None:
        return
    try:
        if int(quantity) > int(max_items):
            findings.deny("CONSTRAINT_VIOLATED", f"The quantity {quantity} exceeds max_items {max_items}.")
    except (TypeError, ValueError):
        findings.deny("ACTION_MALFORMED", "quantity or max_items is not an integer.")


def _check_family(agreement: Mapping[str, Any] | None, mandate: Mapping[str, Any], findings: _Findings) -> None:
    """A live intent may not allocate more than the signed parent set."""

    embedded = mandate.get("parent_limits") or {}
    parent = (agreement or {}).get("parent_limits") or embedded
    if agreement is not None and embedded and agreement.get("parent_limits"):
        if coerce(dict(embedded)) != coerce(dict(agreement["parent_limits"])):
            findings.deny("LIMIT_INCONSISTENT", "The mandate parent limits do not match the agreement parent limits.")
    intent = mandate.get("intent") or {}
    limits = mandate.get("limits") or {}
    if parent.get("maximum_amount") is not None and intent.get("maximum_amount") is not None:
        if money(intent["maximum_amount"]) > money(parent["maximum_amount"]):
            findings.deny("LIMIT_INCONSISTENT", "This intent's per-transaction ceiling exceeds the signed parent set.")
    if parent.get("cumulative_maximum") is not None and limits.get("cumulative_maximum") is not None:
        if money(limits["cumulative_maximum"]) > money(parent["cumulative_maximum"]):
            findings.deny("LIMIT_INCONSISTENT", "This intent's cumulative slice exceeds the signed parent set.")
    if agreement is None or parent.get("cumulative_maximum") is None:
        return
    total = Decimal(0)
    for item in agreement.get("mandates") or []:
        if not isinstance(item, dict):
            findings.deny("LIMIT_INCONSISTENT", "A live intent could not be read.")
            return
        slice_value = (item.get("limits") or {}).get("cumulative_maximum")
        if slice_value is None:
            findings.deny("LIMIT_INCONSISTENT", "A live intent has no cumulative slice under a parent total.")
            return
        total += money(slice_value)
    if total > money(parent["cumulative_maximum"]):
        findings.deny("LIMIT_INCONSISTENT", "The live intents allocate more than the parent cumulative limit.")


def _exceeds(claimed: Any, signed: Any) -> bool:
    try:
        return money(claimed) > money(signed)
    except KataError:
        return True


def _check_asserted(
    mandate: Mapping[str, Any],
    action: Mapping[str, Any],
    asserted_intent: Mapping[str, Any] | None,
    findings: _Findings,
) -> None:
    asserted = asserted_intent
    if asserted is None:
        asserted = (action.get("parameters") or {}).get("asserted_intent")
    if not isinstance(asserted, Mapping):
        return
    signed = mandate.get("intent") or {}
    signed_limits = mandate.get("limits") or {}
    for key, value in asserted.items():
        if key == "cumulative_maximum":
            signed_value = signed_limits.get("cumulative_maximum")
            if signed_value is None or _exceeds(value, signed_value):
                findings.deny(
                    "ASSERTED_INTENT_MISMATCH",
                    "The agent asserted a cumulative total above the signed slice.",
                )
            continue
        if key == "maximum_amount":
            signed_value = signed.get("maximum_amount")
            if signed_value is None or _exceeds(value, signed_value):
                findings.deny(
                    "ASSERTED_INTENT_MISMATCH",
                    "The agent asserted a per-transaction amount above the signed ceiling.",
                )
            continue
        if key not in signed:
            findings.deny("ASSERTED_INTENT_MISMATCH", f"The agent asserted {key}, which is not in the signed intent.")
            continue
        if key == "allowed_actions":
            signed_actions = signed.get("allowed_actions")
            if not isinstance(value, list) or not isinstance(signed_actions, list) or not set(value) <= set(signed_actions):
                findings.deny("ASSERTED_INTENT_MISMATCH", "The agent asserted actions outside the signed intent.")
            continue
        if key == "merchant_constraints":
            signed_merchants = signed.get("merchant_constraints") or []
            if not isinstance(value, list) or (signed_merchants and (not value or not set(value) <= set(signed_merchants))):
                findings.deny("ASSERTED_INTENT_MISMATCH", "The agent asserted merchants outside the signed intent.")
            continue
        if key == "time_limit":
            try:
                later = parse_time(str(value)) > parse_time(str(signed.get("time_limit")))
            except (KataError, TypeError):
                later = True
            if signed.get("time_limit") is None or later:
                findings.deny("ASSERTED_INTENT_MISMATCH", "The agent asserted an expiry later than the signed intent.")
            continue
        if not _same(value, signed[key]):
            findings.deny(
                "ASSERTED_INTENT_MISMATCH",
                f"The agent asserted a different {key} than the principal signed.",
            )


def _check_binding(
    mandate: Mapping[str, Any],
    agent_id: str | None,
    agent_public_key: PublicKey | None,
    findings: _Findings,
) -> None:
    bound = (mandate.get("agent") or {}).get("agent_id")
    if agent_id is not None and agent_id != bound:
        findings.deny("AGENT_BINDING_MISMATCH", "The action's agent is not the agent named in the mandate.")
    fingerprint = (mandate.get("agent") or {}).get("public_key_fingerprint")
    if agent_public_key is not None and agent_public_key.fingerprint != fingerprint:
        findings.deny("AGENT_BINDING_MISMATCH", "The agent key is not the key named in the mandate.")


def _check_delegation(
    mandate: Mapping[str, Any],
    action: Mapping[str, Any],
    delegation: Mapping[str, Any] | None,
    proposed_at: datetime | None,
    now: datetime,
    findings: _Findings,
) -> None:
    if delegation is None:
        return
    status = delegation.get("status")
    if status not in (None, "active"):
        findings.deny("DELEGATION_NOT_ACTIVE", "The delegation is not active.")
    expires_at = delegation.get("expires_at")
    if expires_at:
        expiry = parse_time(str(expires_at))
        if (proposed_at and proposed_at > expiry) or now > expiry:
            findings.deny("DELEGATION_NOT_ACTIVE", "The delegation expired.")
    scope = delegation.get("scope") or {}
    intent = mandate.get("intent") or {}
    intent_ids = scope.get("intent_ids")
    if isinstance(intent_ids, list) and intent.get("intent_id") not in intent_ids:
        findings.deny("DELEGATION_SCOPE_MISMATCH", "The intent is not one of the intents on the delegation.")
    amount = action.get("amount")
    if amount is not None and scope.get("maximum_amount") is not None and money(amount) > money(scope["maximum_amount"]):
        findings.deny("AMOUNT_ABOVE_INTENT_CEILING", "The amount exceeds the delegation ceiling.")
        findings.deny("ACTION_EXCEEDS_INTENT", "The action is outside the signed intent.")
        findings.deny("DELEGATION_SCOPE_MISMATCH", "The amount exceeds the delegation scope.")
    if amount is not None and scope.get("cumulative_maximum") is not None and money(amount) > money(scope["cumulative_maximum"]):
        findings.deny("CUMULATIVE_LIMIT_EXCEEDED", "The amount exceeds the delegation's cumulative total.")
        findings.deny("DELEGATION_SCOPE_MISMATCH", "The amount exceeds the delegation scope.")
    verbs = scope.get("allowed_action_verbs")
    if isinstance(verbs, list) and action.get("action_type") not in verbs:
        findings.deny("ACTION_NOT_ALLOWED", "The action is outside the delegation verbs.")
        findings.deny("DELEGATION_SCOPE_MISMATCH", "The action verb is outside the delegation scope.")
    delegated_agent = (delegation.get("agent") or {}).get("agent_id")
    if delegated_agent and delegated_agent != (mandate.get("agent") or {}).get("agent_id"):
        findings.deny("AGENT_BINDING_MISMATCH", "The delegation names a different agent.")
    delegated_principal = (delegation.get("principal") or {}).get("id")
    if delegated_principal and delegated_principal != (mandate.get("principal") or {}).get("id"):
        findings.deny("PRINCIPAL_MISMATCH", "The delegation names a different principal.")
    scope_currency = scope.get("currency")
    if scope_currency and action.get("currency") and scope_currency != action.get("currency"):
        findings.deny("CURRENCY_MISMATCH", "The action currency does not match the delegation currency.")


def _check_ledger(
    mandate: Mapping[str, Any],
    action: Mapping[str, Any],
    ledger: Sequence[LedgerEntry | Mapping[str, Any]] | None,
    proposed_at: datetime | None,
    seen_action_ids: set[str] | None,
    findings: _Findings,
    agreement: Mapping[str, Any] | None,
    ledger_head: str | None,
    ledger_sequence: int | None,
    ledger_as_of: str | datetime | None,
    now: datetime,
    policy: Policy,
) -> None:
    limits = mandate.get("limits") or {}
    parent = mandate.get("parent_limits") or {}
    needs_cumulative = limits.get("cumulative_maximum") is not None or parent.get("cumulative_maximum") is not None
    needs_frequency = bool(limits.get("frequency"))
    if ledger is None:
        if needs_cumulative:
            findings.deny(
                "CUMULATIVE_STATE_UNAVAILABLE",
                "A cumulative limit is signed and KATA has no spend ledger for this agreement.",
            )
        if needs_frequency:
            findings.deny(
                "FREQUENCY_STATE_UNAVAILABLE",
                "A frequency limit is signed and KATA has no spend ledger for this agreement.",
            )
        entries: list[LedgerEntry] = []
    else:
        raw_entries = [dict(item) for item in ledger if isinstance(item, Mapping)]
        if len(raw_entries) != len(list(ledger)) or not verify_ledger_chain(raw_entries):
            findings.deny("LEDGER_TAMPERED", "The spend ledger hash chain does not verify.")
            return
        held_sequence = len(raw_entries)
        held_head = raw_entries[-1]["entry_hash"] if raw_entries else None
        if agreement is not None and ledger is agreement.get("ledger") and agreement.get("ledger_sequence") not in (None, held_sequence):
            findings.deny("LEDGER_TAMPERED", "The ledger sequence does not match the entries KATA holds.")
        if needs_cumulative or needs_frequency:
            if ledger_sequence is None:
                findings.deny(
                    "LEDGER_HEAD_MISSING",
                    "This authorization check does not carry the ledger head sequence.",
                )
            elif ledger_sequence < held_sequence:
                findings.deny(
                    "LEDGER_TRUNCATED",
                    f"The authorization check names sequence {ledger_sequence}, and the ledger holds {held_sequence}.",
                )
            elif ledger_sequence > held_sequence or ledger_head != held_head:
                findings.deny(
                    "LEDGER_HEAD_MISMATCH",
                    "The authorization check names a ledger head this ledger does not have.",
                )
            as_of_text = ledger_as_of if ledger_as_of is not None else (agreement or {}).get("ledger_as_of")
            if as_of_text is not None:
                try:
                    if isinstance(as_of_text, datetime):
                        if as_of_text.tzinfo is None:
                            raise KataError("timestamps must include a timezone")
                        as_of_dt = as_of_text.astimezone(timezone.utc)
                    else:
                        as_of_dt = parse_time(str(as_of_text))
                    age = now - as_of_dt
                except KataError:
                    findings.deny("LEDGER_MALFORMED", "The ledger replica time could not be read.")
                    age = None
                if age is not None and age > timedelta(seconds=policy.max_ledger_staleness_seconds):
                    findings.step(
                        "LEDGER_STALE",
                        f"The ledger replica is older than {policy.max_ledger_staleness_seconds} seconds.",
                    )
        entries = []
        for raw in raw_entries:
            try:
                entries.append(LedgerEntry.from_dict(raw))
            except (KataError, KeyError, TypeError):
                findings.deny("LEDGER_MALFORMED", "A ledger entry could not be read.")
                return

    action_id = action.get("action_id")
    if seen_action_ids and action_id in seen_action_ids:
        findings.deny("ACTION_REPLAY", "This action id was already evaluated.")
    if any(entry.action_id == action_id for entry in entries):
        findings.deny("ACTION_REPLAY", "This action id is already in the ledger.")

    idempotency = (action.get("settlement") or {}).get("idempotency_key")
    if idempotency:
        for entry in entries:
            if entry.idempotency_key == idempotency and entry.outcome != "failed":
                findings.deny("ACTION_REPLAY", "This idempotency key was already used for a charge that did not fail.")

    currency = (mandate.get("intent") or {}).get("currency") or limits.get("currency")
    counting = [entry for entry in entries if entry.outcome in _COUNTING]
    for entry in counting:
        if currency and entry.currency != currency:
            findings.deny("CURRENCY_MISMATCH", "The ledger contains a charge in a different currency.")

    intent_id = (mandate.get("intent") or {}).get("intent_id")
    scoped = [entry for entry in counting if entry.intent_id is None or entry.intent_id == intent_id]
    same_currency = not currency or not action.get("currency") or action.get("currency") == currency
    if ledger is not None and action.get("amount") is not None and currency and same_currency:
        projected_amount = money(action["amount"])
        if limits.get("cumulative_maximum") is not None:
            spent = sum((entry.amount for entry in scoped if entry.currency == currency), Decimal(0))
            projected = spent + projected_amount
            if projected > money(limits["cumulative_maximum"]):
                findings.deny(
                    "CUMULATIVE_LIMIT_EXCEEDED",
                    f"This charge would bring the total to {_plain(projected)}, above the cumulative limit of {_plain(money(limits['cumulative_maximum']))}.",
                )
        if parent.get("cumulative_maximum") is not None:
            spent = sum((entry.amount for entry in counting if entry.currency == currency), Decimal(0))
            projected = spent + projected_amount
            if projected > money(parent["cumulative_maximum"]):
                findings.deny(
                    "CUMULATIVE_LIMIT_EXCEEDED",
                    f"This charge would bring the parent total to {_plain(projected)}, above {_plain(money(parent['cumulative_maximum']))}.",
                )

    frequency = limits.get("frequency") or {}
    if needs_frequency and ledger is not None and proposed_at is not None:
        window = _window_start(proposed_at, frequency.get("per"))
        count = sum(1 for entry in scoped if window is None or (window < entry.at <= proposed_at))
        maximum = int(frequency["max_count"])
        if count >= maximum:
            findings.deny(
                "FREQUENCY_LIMIT_EXCEEDED",
                f"The agreement already has {count} charges in this window, and the limit is {maximum}.",
            )


def _check_replay_flags(action: Mapping[str, Any], findings: _Findings) -> None:
    prior = (action.get("settlement") or {}).get("prior_attempt_status")
    if prior == "settled":
        findings.deny(
            "RETRY_FARMING",
            "A previous attempt settled, and this action charges again.",
        )


def _check_over_broad(mandate: Mapping[str, Any], policy: Policy, findings: _Findings, now: datetime) -> None:
    intent = mandate.get("intent") or {}
    missing: list[str] = []
    expiry = mandate.get("expires_at") or intent.get("time_limit")
    if policy.require_time_limit and not expiry:
        missing.append("no expiry")
    purpose = intent.get("purpose")
    ceiling = intent.get("maximum_amount")
    if purpose in MONEY_PURPOSES and policy.require_amount_for_money and ceiling is None:
        missing.append("no per-transaction limit")
    if policy.require_allowed_actions and not intent.get("allowed_actions"):
        missing.append("no allowed actions")
    if (
        policy.unscoped_amount_ceiling is not None
        and ceiling is not None
        and not intent.get("category")
        and not (intent.get("merchant_constraints") or [])
    ):
        currency = intent.get("currency") or policy.reference_currency
        day = now.astimezone(timezone.utc).date().isoformat()
        if currency == policy.reference_currency:
            converted = money(ceiling)
        elif policy.fx_rates is None:
            converted = None
            findings.step("FX_RATE_UNAVAILABLE", "The unscoped ceiling is on and no FX rate source was provided.")
        else:
            try:
                converted = convert_amount(money(ceiling), str(currency), day, policy.reference_currency, policy.fx_rates)
            except KataError:
                converted = None
                findings.step("FX_RATE_UNAVAILABLE", "The FX rate source rejected this currency.")
            if converted is None:
                findings.step(
                    "FX_RATE_UNAVAILABLE",
                    f"No {policy.reference_currency} rate for {currency} on {day}.",
                )
        if converted is not None and converted > money(policy.unscoped_amount_ceiling):
            missing.append(
                f"amount converts to more than {policy.unscoped_amount_ceiling} {policy.reference_currency} with no category and no merchant"
            )
    if missing:
        findings.step("OVER_BROAD_INTENT", "Intent is over-broad: " + ", ".join(missing) + ".")


def _finish(findings: _Findings, mandate_hash_value: str | None) -> Evaluation:
    if findings.denies:
        pairs = findings.denies + findings.steps
        required = "NONE" if any(code not in _APPEALABLE for code, _message in findings.denies) else "HUMAN_APPROVAL"
        return _result("DENY", pairs, mandate_hash_value, required_action=required)
    if findings.steps:
        required = "HUMAN_APPROVAL" if any(code == "OVER_BROAD_INTENT" for code, _message in findings.steps) else "STEP_UP"
        return _result("STEP_UP", findings.steps, mandate_hash_value, required_action=required)
    return _result("ALLOW", [], mandate_hash_value)


def _result(
    verdict: str,
    pairs: list[tuple[str, str]],
    mandate_hash_value: str | None,
    *,
    required_action: str | None = None,
) -> Evaluation:
    if required_action is None:
        required_action = {"ALLOW": "NONE", "STEP_UP": "STEP_UP", "DENY": "NONE"}[verdict]
    decision = {"ALLOW": "ALLOW", "STEP_UP": "STEP_UP", "DENY": "BLOCK"}[verdict]
    return Evaluation(
        verdict=verdict,
        reasons=tuple(code for code, _message in pairs),
        messages=tuple(message for _code, message in pairs),
        kata_decision=decision,
        required_action=required_action,
        mandate_hash=mandate_hash_value,
    )


def _merchant_identifiers(action: Mapping[str, Any]) -> list[str]:
    context = action.get("context") or {}
    parameters = action.get("parameters") or {}
    counterparty = action.get("counterparty") or {}
    values = [
        context.get("merchant"),
        parameters.get("merchant"),
        counterparty.get("domain"),
        counterparty.get("merchant_id"),
        counterparty.get("name"),
    ]
    return [value for value in values if isinstance(value, str) and value]


def _same(left: Any, right: Any) -> bool:
    if isinstance(left, list) and isinstance(right, list):
        if all(isinstance(item, str) for item in left + right):
            return set(left) == set(right)
    try:
        if isinstance(left, (int, float, Decimal, str)) and isinstance(right, (int, float, Decimal, str)):
            if isinstance(left, str) and not isinstance(right, str):
                return False
            if isinstance(right, str) and isinstance(left, str):
                return left == right
            return money(left) == money(right)
    except KataError:
        return False
    return coerce(left) == coerce(right)


def _window_start(proposed_at: datetime, per: str | None) -> datetime | None:
    if per in (None, "agreement"):
        return None
    days = {"P1D": 1, "P7D": 7, "P1M": 30}.get(str(per))
    if days is None:
        return None
    return proposed_at - timedelta(days=days)


def _now(value: str | datetime | None) -> datetime:
    if value is None:
        return datetime.now(timezone.utc)
    if isinstance(value, datetime):
        if value.tzinfo is None:
            raise KataError("timestamps must include a timezone")
        return value.astimezone(timezone.utc)
    return parse_time(value)


def _plain(amount: Decimal) -> str:
    text = format(amount, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return text or "0"
