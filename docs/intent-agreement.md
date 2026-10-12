# KATA Intent Agreement

**Status: Concept / Open Design — not production ready.**

This document specifies how a principal and an agent, and optionally a merchant, a payment provider, or an issuer, establish a verifiable agreement on what the agent may do, and how a proposed action is checked against that agreement.

It is the machinery for KATA's third question: **what was the agent authorized to do?** The fourth question — whether behavior matches that authorization — consumes the same signed record later. This document does not score behavior, and it does not replace the seven-outcome decision in [schemas/decision.json](../schemas/decision.json).

KATA's own objects are authoritative here. AP2 mandates, Verifiable Intent credentials, and OAuth or GNAP grants are evidence that can be mapped into these objects. Field mapping for the commerce mandates stays in [interoperability.md](interoperability.md).

## Decisions

1. **The agreement is a new object.** Delegation stays the answer to who authorized the agent ([delegation-model.md](delegation-model.md), [schemas/delegation.json](../schemas/delegation.json)). The structured intent stays [schemas/intent.json](../schemas/intent.json). The new **intent mandate** is that intent, signed, and bound to one agent key. The new **agreement** is the lifecycle record around the mandate.
2. **`maximum_amount` stays the per-transaction ceiling.** A cumulative cap and a frequency cap are separate fields. They need a running ledger, which the mandate does not contain. That matches the interoperability note that a payment-mandate budget is not `maximum_amount`.
3. **The principal's signature is what makes the intent real.** An intent the agent announces at checkout is not this record. The agent cannot widen a signed mandate. Amendments are a new version, signed again.
4. **The check returns `ALLOW`, `STEP_UP`, or `DENY`.** `DENY` is the KATA decision `BLOCK`. A price miss or a bad charge does not revoke the grant. `REVOKE` and `QUARANTINE` stay decisions of the wider engine, or an explicit signed revocation by the principal.
5. **Amounts stay major units** (`1500`, not `150000` cents), as in the rest of KATA. Canonical JSON gives those numbers one encoding so two languages do not sign different bytes for the same amount.
6. **Version 1 signs with Ed25519**, carried as a flattened JWS (`alg: EdDSA`). Verifiable Intent uses ES256. A second algorithm is a later choice, not a silent alias.

## Where it sits

```mermaid
flowchart TD
    P[Principal reads the rendering] --> S[Principal signs the mandate]
    S --> A[Agreement is active]
    C[Merchant, PSP, or issuer] -.->|optional acknowledgement| A
    AG[Agent proposes an action] --> E[Intent check]
    A --> E
    L[Spend ledger] --> E
    R[Revocation log] --> E
    E --> V{Verdict}
    V --> ALLOW
    V --> STEP_UP
    V --> DENY
    DENY --> BLOCK[KATA decision BLOCK]
    E --> Q4[Later: behavior against this mandate hash]
```

The intent module in [architecture.md](architecture.md) is this check plus the store of mandates. The reference library is the check and the lifecycle, in process. It is not the gateway, and it does not open a network connection.

## Data model

### Intent mandate

Schema: [schemas/intent-mandate.json](../schemas/intent-mandate.json).

| Field | Role |
|---|---|
| `mandate_id`, `version` | Identity of this version. An amendment gets a new id and the next version. |
| `supersedes` | Hash of the signing document of the version it replaces. |
| `principal` | `type` and `id`, as on a delegation, plus the Ed25519 public JWK once signed. `display_name` is signed when present. |
| `agent` | `agent_id`, the public JWK, and `public_key_fingerprint`. The fingerprint is SHA-256 over the raw 32-byte public key, lowercase hex, prefixed `sha256:`. |
| `delegation_id` | The Q2 grant this mandate belongs to, when there is one. |
| `intent` | A [KATA intent](../schemas/intent.json). `maximum_amount` is the per-transaction ceiling. |
| `limits` | Cumulative cap, frequency, merchant denylist, and a restatement of the per-transaction ceiling. See below. |
| `not_before`, `expires_at` | The window. When `intent.time_limit` is also set, it is the same instant as `expires_at`. |
| `required_acknowledgements` | Roles that must countersign before the agreement is active: `agent`, `merchant`, `psp`, `issuer`. |
| `revocation_endpoint` | Where revocation is published. The reference library does not fetch the URL. |
| `rendering` | The human-readable text and its SHA-256. Both are inside the signature. |
| `signature` | Flattened JWS over the signing document. |

The signing document is those fields except `signature`, plus `"kata_mandate": "1"`. The JWS protected header is `{"alg":"EdDSA","kid":"<fingerprint>","typ":"kata-mandate+jws"}`. Header and payload are both canonical JSON.

`limits.per_transaction_maximum`, when present, equals `intent.maximum_amount`. It is a restatement so a reader of the agreement sees the ceiling next to the cumulative cap. It is not a second, looser ceiling.

`limits.cumulative_maximum` is the total that may be charged under the agreement, in `limits.currency` (the intent currency).

`limits.frequency` is `{max_count, per}`. `per` is `agreement` (the whole window), `P1D` (one day), `P7D` (seven days), or `P1M` (thirty days, not a calendar month).

`limits.merchant_denylist` refuses merchants even when `intent.merchant_constraints` is empty. An empty `merchant_constraints` array still means no allowlist, as in the intent schema.

### Agreement record

Schema: [schemas/agreement.json](../schemas/agreement.json).

| Field | Role |
|---|---|
| `agreement_id` | Stable id across versions. |
| `status` | `proposed`, `clarifying`, `accepted`, `active`, `revoked`, `expired`. Advisory. The evaluator does not treat the word `active` as authority. |
| `mandate` | The current signed version. |
| `mandate_history` | Superseded versions, retained. |
| `acknowledgements` | Countersignatures of a mandate hash. |
| `revocation` | A signed revocation, when the record still contains it. |
| `events` | The audit log. |
| `created_at`, `updated_at` | Informational. Not signed. |

An acknowledgement is a JWS (`typ: kata-ack+jws`) over `kata_ack`, `agreement_id`, `mandate_hash`, `role`, `id`, `at`, and the acknowledging public key. An agent acknowledgement must use the key named in the mandate. A merchant, PSP, or issuer acknowledgement proves that the holder of the embedded key saw this mandate hash. It does not, by itself, prove the key belongs to that institution. Binding institution keys is an open question.

A revocation is a JWS (`typ: kata-revocation+jws`) over `kata_revocation`, `agreement_id`, `mandate_hash`, `at`, and `reason`. The reference implementation accepts a revocation only from the principal key that signed the mandate.

### Canonical JSON

Signatures are over UTF-8 JSON with:

- object keys sorted by UTF-16 code units
- no insignificant whitespace
- strings escaped as JSON, and U+2028 / U+2029 escaped as well
- numbers in base 10, no exponent, no leading zero, no trailing fractional zero, and no decimal point when the value is an integer

`1`, `1.0`, and `1.00` are the same amount and encode as `1`. `1.50` encodes as `1.5`. Non-finite numbers are rejected. This is the RFC 8785 shape for the types the library emits. A language-default serializer that writes `1.0` will not verify.

### What the signature does not cover

The event log, `status`, `created_at`, and `updated_at` are outside the mandate signature. Each event stores `event_hash`, the SHA-256 of the canonical event with that field removed, and `prev_event_hash` of the previous event. An edit in the middle no longer matches.

That chain does not stop the holder of the file from dropping the tail and keeping an older prefix: the prefix still hashes. A verifier that has stored a previous head can pass it as `expected_log_head` and detect the drop. A verifier that has not seen the log before cannot.

Revocation distribution is the control for that gap, not the hash chain. See [Threats](#threats).

## Human-readable rendering

The hardest fraud problem at grant time is a principal signing limits they did not read, or reading a sentence the agent rewrote. Version 1 makes the confirmation text part of the signed document. The reference renderer produces a fixed sequence of lines from the structured fields. Verifiers recompute the text. A stored rendering that differs does not verify.

Whitespace inside the quoted instruction is collapsed to single spaces, so a newline in the source cannot push the ceilings below a one-line display.

For the laptop instruction the renderer produces:

```text
You (K. Uluer, usr_9182) authorize agent shopper-01 to purchase.
Agent key: sha256:<fingerprint of the bound agent>.
Your words: "Find and buy a laptop for me, maximum CAD 1,500.".
Up to 1500 CAD per transaction.
Up to 1500 CAD in total under this agreement.
Category: electronics.
Merchants allowed: any.
Allowed actions: search, compare, purchase.
Valid from 2026-10-04T13:55:00Z until 2026-10-10T23:59:59Z.
Delegation: dlg_77.
The agent cannot change these limits. You can revoke this agreement.
```

`accept` takes the text the principal was shown. If it differs from the text just rendered, the library refuses to sign. The line order is normative for `kata_mandate` version `1`. A later version may change the words; it must not pretend to be version 1.

The rendering is English and fixed. Localization, and who must display it (wallet, AI application, merchant), are open.

## Lifecycle

```mermaid
flowchart LR
    P[proposed] --> C[clarifying]
    P --> A[accepted]
    C --> A
    A --> G[active]
    G --> G2[active after amend]
    P --> X[revoked]
    C --> X
    A --> X
    G --> X
    G --> E[expired]
    A --> E
```

| Step | Who | What is recorded |
|---|---|---|
| Propose | Agent, principal, or a policy actor | Unsigned draft. Event `proposed`. |
| Clarify | Any party | The draft is replaced. Event `clarified`. Status `clarifying`. Nothing is signed yet, so a clarification cannot widen a grant that does not exist. |
| Accept | Principal, with the principal's key | Rendering and Ed25519 signature. Event `accepted`. If every required acknowledgement is already present, event `activated` and status `active`. Otherwise status `accepted`. |
| Acknowledge | Agent, merchant, PSP, or issuer | Countersignature of the current mandate hash. Event `acknowledged`. The agreement becomes `active` when the required roles are covered. |
| Amend | Principal | New mandate version, previous version moved to history, old acknowledgements dropped. Event `amended`. The old hash no longer authorizes an action. |
| Revoke | Principal | Signed revocation. Event `revoked`. Status `revoked`. The revocation object is also returned so a log outside the agreement can store it. |
| Expire | Time | Evaluation denies once `now` or the action time is past the window, even if nobody has written an `expired` event. `expire` records the event when called after the window. |

Renewal is a new grant or a new version. It is not a silent extension of `expires_at`.

Default required acknowledgements are none. The principal's signature plus the bound agent key is enough to become active. Requiring an agent countersignature, or a merchant or issuer acknowledgement, is a field on the mandate (`required_acknowledgements`), so stripping it breaks the signature.

## Verification

```text
evaluate(agreement or mandate, action) -> ALLOW | STEP_UP | DENY
```

Inputs beyond the action:

| Input | Why |
|---|---|
| Principal public key the verifier expects | The embedded JWK only proves the signature matches itself. Passing the expected key binds it to the principal the verifier already knows. Omitting it is `STEP_UP` / `PRINCIPAL_KEY_UNBOUND`. |
| Agent id and agent public key | Checked against the bound agent. |
| Ledger of prior charges | Required to enforce cumulative and frequency limits. `[]` means nothing has been spent. `None` means the verifier does not know, which steps up. |
| `now` | The verifier's clock. Expiry is enforced here, not only at issuance. |
| `seen_action_ids` | Replay of an action id. |
| `extra_revocations` | Signed revocations from a log the verifier trusts. |
| `expected_log_head` | A log head the verifier has seen before. |
| `revocation_checked` | Caller affirms it consulted `revocation_endpoint`. |
| `delegation` | Optional Q2 cross-check: status, expiry, intent id, ceiling, verbs, agent, principal. |
| `asserted_intent` | An intent the agent claims, including one stuffed into `action.parameters.asserted_intent`. |

The signature is checked first. If it fails, the result is `DENY` and the other fields are not interpreted. A tampered ceiling must not produce a tidy "amount exceeded" reason about attacker-controlled numbers.

When the signature holds, every other check runs. A `DENY` reason wins over a `STEP_UP` reason. Both are returned, deny codes first, so the principal sees the whole set.

| Verdict | KATA `decision` | `required_action` |
|---|---|---|
| `ALLOW` | `ALLOW` | `NONE` |
| `STEP_UP` | `STEP_UP` | `STEP_UP`, or `HUMAN_APPROVAL` when the reason is `OVER_BROAD_INTENT` |
| `DENY` | `BLOCK` | `HUMAN_APPROVAL` when every deny reason is a limit the principal could widen on purpose (amount, merchant, category, frequency, cumulative, a verb). `NONE` when the failure is integrity, revocation, expiry, replay, a price or fee miss, or a bad key. |

There is no risk score. The decision schema's score is a different layer, and this library will not invent one.

### Reason codes

Integrity and authority, all `DENY`:

| Code | When |
|---|---|
| `MANDATE_SIGNATURE_INVALID` | Missing or bad signature. |
| `MANDATE_TAMPERED` | The signed bytes and the mandate fields differ. |
| `MANDATE_NOT_ACTIVE` | The principal has not signed. |
| `PRINCIPAL_KEY_MISMATCH` | The expected principal key is not the signing key. |
| `RENDERING_MISMATCH` | The stored words do not match the renderer, or the hash does not match the words. |
| `AGREEMENT_LOG_TAMPERED` | The event chain, a pinned head, or a revocation marker does not verify. |
| `AGREEMENT_MALFORMED` | The object is neither a mandate nor an agreement. |
| `MANDATE_REVOKED` | A valid principal revocation for this agreement and this mandate hash. |
| `MANDATE_EXPIRED` | `now` or the action time is past the window. |
| `MANDATE_NOT_YET_VALID` | The action is before `not_before`. |
| `WINDOW_INCONSISTENT` | `expires_at` and `intent.time_limit` disagree. |
| `ACK_SIGNATURE_INVALID`, `ACK_KEY_MISMATCH` | A countersignature on the current hash is bad, or the agent used the wrong key. |

Scope, `DENY` unless noted:

| Code | When |
|---|---|
| `ACTION_NOT_ALLOWED`, `ACTION_EXCEEDS_INTENT` | The verb is outside `allowed_actions` or the delegation's verbs. The amount codes also add `ACTION_EXCEEDS_INTENT`, which is the code the shopping-agent example already uses. |
| `AMOUNT_ABOVE_INTENT_CEILING` | Above `maximum_amount` or the delegation ceiling. |
| `CUMULATIVE_LIMIT_EXCEEDED` | Prior counted charges plus this amount exceed `cumulative_maximum`. |
| `FREQUENCY_LIMIT_EXCEEDED` | The window already holds `max_count` counted charges. |
| `CURRENCY_MISMATCH` | Action, intent, delegation, or ledger currency disagree. No conversion is attempted. |
| `MERCHANT_NOT_ALLOWED` | Misses a non-empty allowlist, or hits the denylist. |
| `CATEGORY_MISMATCH` | The action states a category and it is not the intent category. An action that states no category is not failed for that alone. |
| `COUNTERPARTY_NOT_ALLOWED` | Merchant id or settlement address outside the signed lists. |
| `SETTLEMENT_ADDRESS_MISMATCH` | `settlement_address` and `registered_settlement_address` are both present and differ. |
| `COUNTERPARTY_RISK_EXCEEDED` | Observed risk is above `counterparty_constraints.maximum_risk`. |
| `CONSTRAINT_VIOLATED` | `parameters.quantity` is above `constraints.max_items`. Other constraint keys are carried and not interpreted. |
| `CHARGE_EXCEEDS_QUOTE`, `CHARGE_EXCEEDS_LISTED` | Charge is above the reference times `tolerance_ratio`. The comparison is `charge <= reference * tolerance`. Equality with the quote is not the test. |
| `UNDISCLOSED_FEE` | A non-item line is not disclosed, and `allow_undisclosed` is false. A missing `disclosed` flag counts as not disclosed. |
| `FEE_NOT_ACCEPTED` | A non-item fee code is outside `allowed_codes`. |
| `DELEGATION_NOT_ACTIVE`, `DELEGATION_SCOPE_MISMATCH`, `PRINCIPAL_MISMATCH` | Only when the caller passes a delegation. |
| `AGENT_BINDING_MISMATCH` | The acting agent or key is not the bound one. |
| `ASSERTED_INTENT_MISMATCH` | A field the agent asserted is not equal to the signed intent. The signed mandate is what gets evaluated. |
| `MANDATE_SUPERSEDED` | The action names a mandate hash that is not the current version. |
| `ACTION_REPLAY` | The action id was already seen or is in the ledger, or the idempotency key was already used for a charge whose outcome was not `failed`. |
| `RETRY_FARMING` | `settlement.prior_attempt_status` is `settled`. A prior status of `failed` is not this code. |
| `ACTION_MALFORMED`, `LEDGER_MALFORMED`, `LIMIT_INCONSISTENT` | The action, the ledger, or the signed limits cannot be read safely. |
| `ACTION_TIME_IN_FUTURE` | The action time is more than the skew (default 120 seconds) ahead of `now`. |

`STEP_UP`:

| Code | When |
|---|---|
| `PRINCIPAL_KEY_UNBOUND` | Signature matches the embedded key, and the caller did not pass the principal key it expects. |
| `OVER_BROAD_INTENT` | A money purpose has no ceiling, or there is no expiry, or there are no allowed actions. `required_action` is `HUMAN_APPROVAL`. A policy may also flag a high ceiling with no category and no merchant; that threshold is off unless the caller sets it. |
| `CUMULATIVE_STATE_UNAVAILABLE`, `FREQUENCY_STATE_UNAVAILABLE` | The mandate has that limit and the ledger was omitted. |
| `COUNTERPARTY_ACK_REQUIRED` | A required acknowledgement for the current hash is missing. |
| `REVOCATION_ENDPOINT_UNCHECKED` | The mandate names an endpoint and the caller has not set `revocation_checked`. |
| `AMOUNT_NOT_PROVIDED` | A money action, or an action under a price expectation, has no amount. |
| `TOLERANCE_NOT_DECLARED` | A quote or list is signed and `tolerance_ratio` is absent. The library will not assume `1`. |
| `COUNTERPARTY_RISK_UNKNOWN` | The mandate caps counterparty risk and the action has no `low` / `medium` / `high` risk. |

Ledger outcomes `allowed`, `authorized`, and `settled` count toward cumulative and frequency. `failed` does not. A price check runs only when the intent has `price_expectation`. A ceiling is never copied into `quoted_price`.

An action inside the window is not failed for being old. Replay is an id and an idempotency key, not a second look at the clock.

## Threats

These sit under the assets already named in [threat-model.md](threat-model.md): intent objects, delegation records, and the decision trail. The rows below are the ones this design takes a position on.

| Threat | What the agreement does |
|---|---|
| **Prompt injection that widens scope** | The evaluator reads the signed mandate, not an intent in the tool output. If the action carries `parameters.asserted_intent` and any stated field differs, the verdict is `DENY` / `ASSERTED_INTENT_MISMATCH`. The agent has no key that can amend the mandate. |
| **Mandate tampering** | Any change to a signed field, including the rendering, fails verification before amount checks run. |
| **Replay** | A repeated action id, or an idempotency key already used for a non-failed charge, is `ACTION_REPLAY`. A settled attempt that is charged again is `RETRY_FARMING`. A retry after `failed` is not. |
| **Over-broad intent** | Missing expiry, missing ceiling on a money purpose, or missing verbs is `STEP_UP` / `OVER_BROAD_INTENT`, with `HUMAN_APPROVAL`. The default does not invent a currency-blind amount threshold. Empty merchant constraints remain "no allowlist", which is a real choice the rendering states as "Merchants allowed: any." |
| **Signing what you did not read** | The words are inside the signature, recomputed by the verifier, and tied to the agent key fingerprint. A swapped agent key changes the sentence. |
| **Approval fatigue** | A quote, list, or undisclosed-fee miss is `DENY` with `required_action` `NONE`. The principal is not asked to rubber-stamp the same charge. Widening the grant is an amendment, which produces a new rendering. |
| **Revocation stripped from the copy the agent shows** | A revocation inside the record is enough to deny. Absence is not enough to allow. Verifiers pass `extra_revocations` from a log they trust, or pin `expected_log_head`. If the mandate names `revocation_endpoint`, evaluation steps up until the caller says that endpoint was checked. The library does not fetch it. Short expiry bounds the window in which a missed revocation still works. |
| **Self-signed principal key** | Verification against the embedded JWK proves the signature matches that key. It does not prove the key is the human. `PRINCIPAL_KEY_UNBOUND` steps up until the verifier supplies the key it already associates with the principal. WebAuthn and verifiable credentials remain the way that association is made. |
| **Counterparty overcharge** | Quote, list, and fee checks can `DENY` the action. They do not revoke the mandate. |
| **Honest price movement** | A tolerance band is required before a quote is compared. The band is the one the principal signed for this intent. |

Upstream account takeover of the AI application is unchanged from the threat model: a real principal key can sign a real mandate for the attacker's purchase. This layer will show a valid signature. Per-session step-up to the human is still the control, and it belongs to the wider decision, not to a second copy of the mandate.

## Interoperability

KATA does not adopt AP2, Verifiable Intent, OAuth, or GNAP as the mandate format. A verified credential is evidence. The intent check still runs, and its verdict is a KATA verdict.

| Source | What it can fill | What it does not decide |
|---|---|---|
| **AP2 v0.2** open mandate plus a closed mandate that satisfies it | Principal and agent keys, `maximum_amount` from `payment.amount_range.max` after minor-to-major conversion, merchant and payee lists, `expires_at` from `exp`. Cumulative `payment.budget` maps to `limits.cumulative_maximum`, not to `maximum_amount`. | Behaviour, quote versus charge, the seven decisions. AP2 receipts accept or reject a mandate. |
| **Verifiable Intent** autonomous chain | Same shape: L2 constraints become the intent, L2 `cnf` is the agent key, L2 `exp` is the window. `mandate.payment.budget` is the cumulative cap. | Same gaps. VI's checker is pass or violation. |
| **OAuth 2.0** | A token is delegation evidence (Q2), the way [standards.md](../research/standards.md) already says. A scope string is not an intent. | Amount, merchant, price, revocation of a KATA mandate. |
| **RFC 9396 Rich Authorization Requests** | `authorization_details` can *carry* a KATA intent object as a JSON value. The type URI would be KATA's, and the schema would stay this one. | RAR does not define the check. |
| **GNAP (RFC 9635)** | The negotiate-then-grant loop is the same shape as clarify then accept. A GNAP access token can be delegation evidence. Subject identifiers can name the principal. | GNAP access rights are resource descriptors. They are not a ceiling, a tolerance band, or a behavior hook. |
| **W3C Verifiable Credentials** | A natural later envelope for the same signing document, once the fields are stable. Agent badges remain Q1 evidence. | This version does not wrap the mandate in a VC. |
| **Visa Trusted Agent Protocol, Web Bot Auth** | Q1, the agent key. | No purchase constraints. |

Two conversions that are easy to get wrong, and that this spec does not do:

- Do not map an amount ceiling onto `price_expectation.quoted_price`.
- Do not treat an AP2 or VI minor-unit integer as a KATA major-unit amount.

Worked mappings of the commerce fields remain [interoperability.md](interoperability.md). The reference library does not parse an AP2 JWS or an SD-JWT.

## Reference implementation

[`reference/python`](../reference/python) is a Python library. Tests cover signing, tampering, the lifecycle, the laptop amounts, price and fees, cumulative and frequency state, replay, revocation stripping, and schema validation. `examples/purchase_check.py` signs the CAD 1,500 laptop intent, allows a CAD 1,300 purchase, denies a CAD 4,200 purchase, then revokes and denies the in-scope purchase.

| Implemented | Stubbed or absent |
|---|---|
| Create, render, sign, and verify a mandate | Natural-language parsing into an intent. The caller supplies the structured intent. |
| Propose, clarify, accept, acknowledge, amend, revoke, expire | An HTTP API, a gateway, or storage |
| `ALLOW` / `STEP_UP` / `DENY` with the reason codes above | Risk scores, behavior profiles, drift across a session |
| Cumulative and frequency checks against a caller-supplied ledger | The ledger itself, and who is authoritative for it |
| Revocation signatures, an external revocation list, a pinned log head, step-up when a named endpoint was not checked | Fetching the endpoint, pushing revocation, a transparency log |
| Price band, fees, merchant, category, settlement mismatch, `max_items` | A general constraint language. Other `constraints` keys are stored only. |
| Optional delegation cross-check when the caller passes the delegation | Walking an agent-to-agent delegation chain |
| Ed25519 JWS | ES256, SD-JWT, selective disclosure |
| English rendering, version 1 | Localized rendering |

Demo keys in the example are derived from public seeds.

## Roadmap

The next slices, in the order they unblock each other:

1. **Revocation status.** A signed log a merchant or issuer can query, with a freshness bound. The endpoint field and `extra_revocations` are the hook. Fetching and caching are not done.
2. **Ledger authority.** Decide who holds the cumulative total — issuer, PSP, merchant, or a KATA log — and the maximum age of that total before the check steps up. The library already steps up when the total is missing.
3. **Full evaluator.** Identity, delegation freshness, and behavior around this verdict, emitting the seven decisions. Still no calibrated score until there is a measurement.
4. **Intent capture.** Propose a structured intent from the instruction, then require the rendering as the confirmation. The parser is a separate component so a bad parse cannot sign itself.
5. **Algorithm agility.** ES256 as a second JWS algorithm so a Verifiable Intent key can countersign without a bridge. Version the signing document rather than overloading `kata_mandate` `1`.
6. **Counterparty profiles.** When a payment requires a merchant, PSP, or issuer acknowledgement, and how those keys are pinned.
7. **Evaluation against AgentCommerceBench.** Run the reference check on the classes it can see (amount, category, quote, list, fees, replay, payee). Report recall at a stated false-positive budget. Do not cite a coverage number before that run. Silent downgrade still needs delivery evidence this layer does not have.
8. **Envelope.** Only after the fields settle: VC packaging, or carrying the intent inside RAR `authorization_details`. Not a second schema.

## Open questions

These are the choices the reference implementation made that Kaan should confirm or reverse.

1. **Separate objects.** Mandate and agreement are not folded into the delegation. Is that the split you want, or should a later version make the signed intent a part of the delegation record?
2. **Per-transaction versus cumulative.** `maximum_amount` remains per transaction. The cumulative cap is `limits.cumulative_maximum`. Confirm, or say the single field was always the total.
3. **Who holds the ledger,** and how stale it may be before `CUMULATIVE_STATE_UNAVAILABLE` becomes `DENY` instead of `STEP_UP`.
4. **Activation.** Principal signature alone makes the agreement active. Should the agent have to countersign first? Should a payment require an issuer or PSP acknowledgement before `active`?
5. **Over-broad defaults.** Missing expiry, missing ceiling, or missing verbs step up for human approval. They do not hard-deny. Is step-up the right default for a payment?
6. **Unscoped amount.** There is no default maximum for "any merchant, any category". The policy knob exists and is off, because a single number is not meaningful across currencies. Do you want a per-currency table?
7. **Units and algorithms.** Major units and Ed25519 for version 1. VI and AP2 use integer minor units and ES256. Keep KATA's units and add ES256 later, or sign minor units in the payload now?
8. **Revocation absence.** A missing revocation in the agent-presented record does not prove the grant is live. Is step-up mandatory for every payment until an endpoint is checked, even when the mandate names no endpoint?
9. **Who else may revoke.** Only the signing principal key. Should a named policy key be able to revoke without the principal, and which institution holds it?
10. **Price misses.** They block the action and do not revoke the grant. Confirm that a cheating merchant must not automatically `REVOKE` a good delegation.
11. **Frequency month.** `P1M` is thirty days. A calendar month is a different rule.
12. **Rendering.** English, versioned, and signed. Who is responsible for showing it, and what happens if a wallet shows a translation that the signature does not cover?
13. **One intent per agreement.** An amendment replaces the intent version. A delegation may still list several intent ids. Should one agreement be allowed to hold several live intents?
14. **Asserted intent.** Any stated field that is not equal to the signed field is a mismatch, including a narrower echo. A subset rule would accept "I will only spend 100" under a 1,500 ceiling. Equality is stricter and easier to explain.
