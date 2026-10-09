# Interoperability

**Status: Concept / Open Design — not production ready.**

KATA does not replace the protocols below. A verified mandate or credential is evidence for one or more of the four KATA questions. It is not a KATA decision. KATA still has to score behavior, compare price integrity, and return one of seven decisions.

KATA is an independent open framework. It is **not affiliated with** Mastercard, Google, Visa, AGNTCY, W3C, or any other organization named here. Citations are descriptive. Spec text is quoted only to name fields that exist.

Field-level mapping for commerce mandates is in this document. The landscape survey stays in [research/standards.md](../research/standards.md).

## Sources read

| Protocol | What was read | Version | Commit |
|---|---|---|---|
| [Verifiable Intent](https://github.com/agent-intent/verifiable-intent) | `README.md`, `CHANGELOG.md`, `spec/README.md`, `spec/credential-format.md`, `spec/constraints.md`, `examples/autonomous_flow.py`, `examples/helpers.py` | Spec **0.1-draft** (2026-02-18). Changelog **0.1.0** (2026-02-19). README: draft v0.1, maintained by Mastercard. | `356c29635f1c44df7de02edb58699ca9f29bece6` (2026-04-20) |
| [AP2](https://github.com/google-agentic-commerce/AP2) | `docs/ap2/specification.md` ("Agentic Payment Protocol (v0.2)"), `checkout_mandate.md`, `payment_mandate.md`, `flows.md`, `CHANGELOG.md`, `code/sdk/schemas/ap2/*.json` | **v0.2**. Changelog 0.2.0 (2026-04-28), feature commit `b4587ac`. | `e1ea56db72a6385bce3e5c1112b3a56ce60acb43` |
| AP2 v0.1 types | `src/ap2/types/mandate.py`, `src/ap2/types/payment_request.py` at the 0.1.0 commit | **0.1.0** (2025-09-16) | `e66fc0b8f3f3c69fbabae721a4c57a18cf28c4b7` |
| [Visa Trusted Agent Protocol](https://github.com/visa/trusted-agent-protocol) | `README.md`, `tap-agent/README.md`, `agent-registry/README.md`, `agent-registry/schemas.py` | Sample repository. No separate spec version. | `16d59bdf3f8a542bc538d0962edbb80ea30a02af` (2025-10-28) |
| [AGNTCY identity](https://github.com/agntcy/identity) | `README.md`, `api/spec/proto/agntcy/identity/core/v1alpha1/id.proto`, `vc.proto` | Proto package `agntcy.identity.core.v1alpha1` | `8f7c1b52b5c4585cbd6308053ff43e076d96927e` (2026-09-29) |

Amounts in Verifiable Intent and in the AP2 JSON schemas are **integer minor units** (ISO 4217). KATA amounts are major units (`400.00`, not `40000`). The worked examples convert with the currency's minor-unit exponent (2 for USD) and say so. They do not treat a spec field as a KATA field of the same name.

## Verifiable Intent

Verifiable Intent (VI) is a layered SD-JWT chain: credential provider to user to agent. README and `spec/README.md`: the issuer signs L1; the user signs L2; in Autonomous mode the agent signs L3. Constraints (amount range, allowed line items, approved merchants) are cryptographically bound. VI verifies that an L3 fulfillment satisfies the disclosed L2 constraints. It does not emit a trust decision, a behavior score, or `REVOKE` / `QUARANTINE`.

Two modes (`spec/README.md` terminology):

- **Immediate.** L1 + L2. `typ` `kb-sd-jwt`. Final values. No `cnf` in the mandates. No `constraints`. No L3.
- **Autonomous.** L1 + L2 + split L3. L2 `typ` `kb-sd-jwt+kb`, with `cnf.jwk` (including `kid`) equal to the agent key. L3a (`vct` `mandate.payment.1`) goes to the payment network. L3b (`vct` `mandate.checkout.1`) goes to the merchant. L3 `typ` is `kb-sd-jwt` and MUST NOT contain `cnf`.

### Where KATA sits

KATA is not the chain verifier. VI verifiers already check the ES256 signature, `sd_hash`, `kid` against `cnf.jwk.kid`, expiry, and constraint satisfaction (`credential-format.md` §4.7 and §5.7).

Call `POST /kata/evaluate` after that verification succeeds and before the merchant accepts L3b or the network accepts L3a. The same request can be made by the agent before it signs L3, using the cart it is about to bind. A failed VI verification is missing evidence: KATA should not treat an unverified chain as a grant.

Immediate mode has no agent delegation. It can still be logged as principal-confirmed action evidence. It does not answer Q4.

### Delegation chain to KATA objects

L2 `aud` "identifies the agent" (`credential-format.md` §4.3). VI has no `agent_id` and no `provider` claim. KATA `agent.provider` is required, so the worked example copies L3 `iss` and labels that copy as a KATA fill.

| VI claim | Where | KATA |
|---|---|---|
| L1 `sub` | `credential-format.md` §3.3, REQUIRED | `delegation.principal.id`, `principal.id`. `principal.type` is KATA (`human`). VI does not carry that enum. |
| L1 `iss` | §3.3 | Evidence of who bound the user key. Not `agent.provider`. |
| L1 `vct`, `pan_last_four`, `scheme`, optional `card_id` | §3.3. Profile claims for `https://credentials.mastercard.com/card`. | Payment-instrument context on the action. Not agent identity. |
| L1 `email` | §3.4, OPTIONAL, selectively disclosable | Not mapped unless the verifier disclosed it. The example has `alice@example.com`. |
| L1 `cnf.jwk` | §3.3 | User key. Principal authentication evidence, not the agent key. |
| L2 `aud` | §4.3 | `agent.agent_id` |
| L2 mandate `cnf.jwk` / `cnf.jwk.kid` | §4.5.1, §4.5.2, §4.6 | `agent.cryptographic_identity` (`mechanism` `jwk`). Header `kid` on L3 MUST match this `kid` (§5.2). |
| L2 `nonce` | §4.3 | `delegation.delegation_id`. VI has no field named `delegation_id`. |
| L2 `iat`, `exp` | §4.3. Autonomous L2 SHOULD be at most 30 days. | `delegation.granted_at`, `delegation.expires_at`, `intent.time_limit` |
| L2 `iss` | §4.3, OPTIONAL | Wallet or user-agent URI. Not the agent provider. |
| `prompt_summary` | §4.5.1, OPTIONAL, on the open checkout mandate | `delegation.purpose`, `intent.natural_language_source` |
| L2 `sd_hash` | §4.3 | Chain evidence that L2 is bound to L1. KATA does not re-specify SD-JWT. |
| L3 `iss` | Example `autonomous_flow.py` sets `https://agent.example.com`. `iss` is OPTIONAL on L2 (§4.3); L3's always-visible table (§5.3) lists `nonce`, `aud`, `iat`, `exp`, `sd_hash`, `delegate_payload`, `_sd_alg`, `_sd` — not `iss`. | Copied into `agent.provider` only because KATA requires `provider`. |
| L3 `aud` | §5.3. L3a payment network, L3b merchant. | Action audience, not a second agent id. |
| L3 `nonce` | §5.3. MUST differ from the L2 nonce. | `action.action_id` in the example. Not `session_id`. |
| `risk_data.device_id`, `risk_data.ip_address` | §4.5.2, OPTIONAL, L2 only, not copied into L3 | Context for the consent event. Not an agent behavior history. |

`intent.intent_id`, `intent.purpose`, and `intent.version` are KATA-required and absent from VI. The example assigns `intent_id`, sets `purpose` to `purchase`, and sets `version` to `1` because the vct suffix is `.1`. Those three are labels, not VI claims.

`delegation.status` is KATA (`active` when the static L2 `exp` is still after the evaluation instant). VI expresses lifetime with `exp`, not that enum.

### Constraints and final values

Eight registered types (`constraints.md` §4). Amounts are integer minor units. Empty allowlists are unsatisfiable (§5).

| VI type | Fields that exist | KATA |
|---|---|---|
| `mandate.checkout.allowed_merchants` | `allowed[]` of `{id? , name, website}`. `name` and `website` REQUIRED; `id` OPTIONAL (§4.1). | `intent.counterparty_constraints.allowed_merchant_ids` from `id` when present. `intent.merchant_constraints` from `website`. |
| `mandate.checkout.line_items` | `items[]` of `{id, acceptable_items[], quantity}`, optional `match_mode` `minimum` (default) or `exact`. Item `{id, title}` both REQUIRED (§4.2). | `intent.constraints` keeps the object. `quantity` is a cap, not a KATA `max_items` field of the same meaning. `match_mode` has no KATA twin. |
| `mandate.payment.allowed_payees` | `allowed[]` of `{id?, name, website}` (§4.3). | Same merchant/payee lists. A payee that is not a merchant id still belongs on `counterparty_constraints`. |
| `mandate.payment.amount_range` | `currency` REQUIRED; `min` and `max` OPTIONAL integers, minor units (§4.4). | `max` → `intent.maximum_amount` and `delegation.scope.maximum_amount` after minor-to-major conversion. `min` stays inside `intent.constraints`. KATA has no minimum amount. |
| `mandate.payment.budget` | `currency`, `max` REQUIRED, `min` OPTIONAL. Cumulative across L3s from one mandate pair (§4.5). Network state. | Not `maximum_amount`. A cumulative cap is a different limit. KATA can store it under `intent.constraints` and still cannot enforce it without the network's running total. |
| `mandate.payment.recurrence` | `frequency` (ISO 20022 codes listed in §4.6), `start_date`, optional `end_date`, optional `number`. Merchant-managed. Ongoing charges leave the VI chain. | No KATA recurrence object. Store the constraint. Do not pretend later merchant charges were re-evaluated. |
| `mandate.payment.agent_recurrence` | `frequency` (`ON_DEMAND` or an ISO 20022 code), `start_date`, `end_date`, optional `max_occurrences`. Requires `amount_range` and `budget` (§4.7). | A standing grant with a count. KATA evaluates each proposed L3. The occurrence counter is network state VI already says a stateless verifier cannot hold. |
| `mandate.payment.reference` | `conditional_transaction_id`, the hash of the L2 checkout disclosure (§4.8). | Binding between the two open mandates. Not an intent id. |

L3a `mandate.payment.1` (`credential-format.md` §5.6): `payment_instrument` `{type, id, description?}`, `payment_amount` `{currency, amount}` integer minor units, `payee` `{id?, name, website}`, `transaction_id` equal to L3b `checkout_hash`, optional `selected_merchant`.

L3b `mandate.checkout.1` (§5.5): `checkout_jwt`, `checkout_hash`, optional `line_items`, optional `prompt_summary`.

`checkout_jwt` payload schema is **implementation-defined** in v0.1 (§6.3). It SHOULD include SKUs, quantities, unit prices, currency, and a merchant identifier. When `mandate.checkout.allowed_merchants` is present, the payload MUST include merchant `id`. The reference example's payload (`helpers.py` `create_checkout_jwt`) uses `cart.items[]` (`sku`, `name`, `size`, `size_label`, `color`, `quantity`, `unitPrice` in dollars) and `cart.subTotal` `{amount, currencyCode}`. It does not include merchant `id`. That is an example gap against §6.3, not a KATA field.

| L3 / checkout value | KATA action |
|---|---|
| `payment_amount.amount` + `currency`, converted | `amount`, `currency`, `price.charged_amount` |
| Example `unitPrice` / catalog `price` (27999 cents in `helpers.py`) | `price.listed_price` only. There is no VI `quoted_price`. |
| `payee.id`, `payee.name`, `payee.website` | `counterparty.merchant_id`, `counterparty.name`, `counterparty.domain` |
| `payment_instrument` | `parameters`. Not a price line. |
| `transaction_id` / `checkout_hash` | `parameters`. The example uses a labeled stand-in because the hash is computed at runtime. |

`price_expectation.quoted_price`, `fee_policy`, `price.fee_breakdown`, `price.peer_price`, and `service.delivered_tier` have no VI source. Leaving them out is the mapping. Inventing a quote from "under $400" would turn a ceiling into a quote.

### What KATA consumes as evidence

A verified Autonomous chain is direct evidence for Q2 and Q3:

- Q2. L1 binds the user key; L2 is signed with that key; L2 `cnf` binds the agent key; L3 is signed with that key.
- Q3. Disclosed constraints are the intent. L3 values that pass VI's checker are inside that intent: merchant, item id, quantity, currency, and amount range.

Q1 is partial. `aud` plus `cnf.jwk.kid` identifies the key the user delegated to. VI does not assert developer, model, deployment, or reputation.

Q4 is absent. `risk_data` is a device snapshot at consent, not a behavior profile.

### What KATA adds

- Behavior risk across sessions, and `agent_spend_baseline`.
- Price integrity against a quote, a list, disclosed fees, and a tolerance band. An amount inside `max` can still be `CHARGE_EXCEEDS_LISTED` when a list price exists and the charge sits outside the band.
- Seven decisions. VI's checker is pass or violation.
- `REVOKE` and `QUARANTINE`. A bad grant is not the same event as a merchant inside an allowlist charging the wrong price. `REVOKE` stays for the grant.
- A decision record (`evaluation_id`, `reasons`, `required_action`) the mandate format does not carry.

### Gaps

**VI does not have:** a decision ladder, behavior history, quote versus charge, fee disclosure, peer price, delivered tier, settlement retry state, or an agent `provider` claim.

**KATA does not have:** SD-JWT selective disclosure, `sd_hash` binding, a minimum amount, `match_mode`, ISO 20022 recurrence, a network-side cumulative budget, or split L3a/L3b presentations. KATA should keep those as evidence, not re-encode them as a second credential format.

**Worked example:** [examples/verifiable-intent/](../examples/verifiable-intent/). Static composition of `examples/autonomous_flow.py` at the commit above, with timestamps taken from `credential-format.md` §3.6 (`iat` `1700000000`) plus the example's L2 lifetime of 86400 seconds and L3 lifetime of 300 seconds. Nonces and hashes that the example draws at runtime are the literal stand-ins `stand-in-l2-nonce`, `stand-in-l3-nonce`, `stand-in-checkout-disclosure-hash`, and `stand-in-checkout-hash`.

## Agent Payments Protocol (AP2)

Current normative text is **v0.2**. It defines a Checkout Mandate and a Payment Mandate, each open or closed (`specification.md`, Mandate Versioning). `vct` values in the JSON schemas are constants:

| Mandate | `vct` const |
|---|---|
| Closed checkout | `mandate.checkout.1` |
| Open checkout | `mandate.checkout.open.1` |
| Closed payment | `mandate.payment.1` |
| Open payment | `mandate.payment.open.1` |

The schema `description` strings say `mandate.checkout` / `mandate.payment` without the suffix. The `const` values and the prose include the suffix. Mappings use the `const`.

v0.2 does **not** contain the strings "Intent Mandate" or "Cart Mandate". Those names are v0.1 (`mandate.py` at `e66fc0b`). See the crosswalk below. [examples/ucp-checkout/](../examples/ucp-checkout/) is an earlier sketch; its property names are not v0.1 or v0.2 fields.

Roles in v0.2 (`specification.md`, Roles): Shopping Agent, Credential Provider, Merchant, Merchant Payment Processor, Trusted Surface. Network is not one of those five; verification and `flows.md` still have the Credential Provider share a Payment Mandate with the payment network. Trusted Surface MUST be non-agentic (Agentic vs Non-Agentic). Human Present: the user signs closed mandates. Human Not Present: the user signs open mandates that carry the agent `cnf`; the agent later signs closed mandates.

### v0.1 names

Commit `e66fc0b`, classes in `src/ap2/types/mandate.py`. Data keys: `ap2.mandates.IntentMandate`, `ap2.mandates.CartMandate`, `ap2.mandates.PaymentMandate`.

| v0.1 object | Fields on the class | Closest v0.2 object |
|---|---|---|
| `IntentMandate` | `user_cart_confirmation_required` (bool, default true), `natural_language_description` (str), `merchants` (optional `list[str]`), `skus` (optional `list[str]`), `requires_refundability` (optional bool, default false), `intent_expiry` (ISO 8601) | Open Checkout Mandate plus open Payment Mandate constraints. v0.2 does not have `natural_language_description`, `skus`, or `requires_refundability`. |
| `CartContents` / `CartMandate` | `id`, `user_cart_confirmation_required`, `payment_request` (W3C PaymentRequest), `cart_expiry`, `merchant_name`; `merchant_authorization` JWT. The JWT payload description names `iss`, `sub`, `aud`, `iat`, `exp`, `jti`, `cart_hash`. | Closed Checkout Mandate bound to `checkout_jwt`, with `checkout_hash`. |
| `PaymentMandateContents` / `PaymentMandate` | `payment_mandate_id`, `payment_details_id`, `payment_details_total` (`PaymentItem`: `label`, `amount.currency`, `amount.value` float, optional `pending`, `refund_period` int default 30), `payment_response` (`request_id`, `method_name`, optional `details`, `shipping_address`, `shipping_option`, `payer_name`, `payer_email`, `payer_phone`), `merchant_agent`, `timestamp`; `user_authorization` verifiable presentation. `PaymentCurrencyAmount.value` is a float, not minor units. | Closed Payment Mandate. v0.2 `payment_amount.amount` is an integer minor units (`types/amount.json`). The float `value` did not survive. |

KATA mapping for those v0.1 fields, if a deployment still sends them:

| v0.1 | KATA |
|---|---|
| `natural_language_description` | `intent.natural_language_source` |
| `merchants` | `intent.merchant_constraints` |
| `skus` | `intent.constraints` (item ids). Not a price. |
| `intent_expiry` / `cart_expiry` | `intent.time_limit` / action expiry context |
| `requires_refundability` | No KATA field. Keep it on the intent `constraints` object. |
| `user_cart_confirmation_required` | Evidence that a human confirmation is still required. Aligns with `HUMAN_APPROVAL` when true. It is not itself a decision. |
| `payment_details_total.amount.value` | `action.amount` in major units already (float). Do not scale it again. |
| `merchant_name` | `counterparty.name` |
| `cart_hash` | Binding evidence, like v0.2 `checkout_hash`. |

### v0.2 fields

Open checkout (`open_checkout_mandate.json`): required `vct`, `constraints`, `cnf`. Optional `iat`, `exp`.

Closed checkout (`checkout_mandate.json`): required `vct`, `checkout_jwt`, `checkout_hash`. Optional `iat`, `exp`. `checkout_hash` is the base64url hash of `checkout_jwt`. Payload of `checkout_jwt` is out of scope except "when used with UCP this MUST be the Checkout object" (`checkout_mandate.md`).

Open payment (`open_payment_mandate.json`): required `vct`, `constraints`, `cnf`. The `constraints` array MUST contain a `payment.reference` (`contains`). Optional closed-mandate properties: `payee`, `payment_amount`, `payment_instrument`, `pisp`, `execution_date`, `risk_data`, `iat`, `exp`.

Closed payment (`payment_mandate.json`): required `vct`, `transaction_id`, `payee`, `payment_amount`, `payment_instrument`. Optional `pisp`, `execution_date`, `risk_data`, `iat`, `exp`.

`types/merchant.json`: required `id`, `name`; optional `website`. This differs from VI, where `name` and `website` are required and `id` is optional. Some AP2 prose examples omit `id` (`checkout.allowed_merchants` example in `checkout_mandate.md`). The schema still requires `id`.

`types/amount.json`: `amount` integer minor units, `currency` ISO 4217. `payment.amount_range.max` is an integer (`open_payment_mandate.json`). The prose example in `payment_mandate.md` writes `"max": 100.50` and `"min": 10.00`. The budget prose example writes `"max": 1000.00`, and `budget.max` in the schema is type `number`, not `integer`. The worked example follows the decoded disclosure (`max` `20000`), which matches the integer schema, not the decimal prose.

`types/payment_instrument.json`: required `id`, `type`; optional `description`. `types/pisp.json`: required `legal_name`, `brand_name`, `domain_name`. `risk_data` is "a map of relevant risk signals" with no registered keys in the schema (VI's keys are `device_id` and `ip_address`; do not copy those onto AP2 unless a credential actually has them).

Constraint `type` strings are **not** `mandate.`-prefixed.

| AP2 `type` | Fields | KATA |
|---|---|---|
| `checkout.allowed_merchants` | `allowed[]` merchants | `counterparty_constraints.allowed_merchant_ids`, `merchant_constraints` from `website` when present |
| `checkout.line_items` | `items[]` `{id, acceptable_items[{id, title}], quantity}` | `intent.constraints`. v0.2 line-item evaluation requires each constraint entry to be fulfilled (flow equal to both quantities). VI's default `match_mode` `minimum` allows a subset. Do not collapse those rules. |
| `payment.allowed_payees` | `allowed[]` merchants | Same as allowed merchants, on the payee |
| `payment.allowed_payment_instruments` | `allowed[]` instruments | `intent.constraints`. KATA has no instrument allowlist field. |
| `payment.allowed_pisps` | `allowed[]` of `legal_name`, `brand_name`, `domain_name` | `intent.constraints`. No KATA PISP object. |
| `payment.amount_range` | `currency`, `max` required integers; `min` optional | `max` → `maximum_amount` after conversion. `min` stays in `constraints`. |
| `payment.budget` | `max` (schema type `number`), `currency` | Cumulative cap. Not `maximum_amount`. |
| `payment.reference` | `conditional_transaction_id` | Links open payment to the open checkout hash. Mapped to `delegation.delegation_id` in the example because it is the stable grant binding in the sample. Not an `intent_id`. |
| `payment.agent_recurrence` | `frequency` enum `ON_DEMAND`, `DAILY`, `WEEKLY`, `BIWEEKLY`, `MONTHLY`, `QUARTERLY`, `ANNUALLY`; optional `max_occurrences` | Standing grant. Not VI's ISO 20022 `mandate.payment.recurrence`, which AP2 v0.2 does not define. |
| `payment.execution_date` | optional `not_before`, `not_after` | Window on the action. KATA `intent.time_limit` is a single expiry; both ends belong in `constraints`. |

Closed payment `payment_amount` maps like VI's L3a amount. `payee` maps to `counterparty`. `transaction_id` is the checkout hash, stored on `parameters`.

The v0.2 checkout example payload (`checkout_mandate.md`, closed example) includes `product.price` `199.0`, `total_price` `199.0`, and `currency` `USD`. That payload is an example. It is not `types/item.json`, which defines `price` as an integer minor unit. The worked example copies `199.0` into `price.listed_price` as written, and copies `payment_amount.amount` `19900` into `action.amount` `199.00` using the amount schema's minor units. Those two readings agree. This document does not invent a `quoted_price`.

`prompt_summary` is a VI field. It is not in the AP2 v0.2 schemas. The sample open mandates do not carry a natural-language claim. v0.1 `natural_language_description` is the earlier field, and only if the payload is actually v0.1.

### Where KATA sits

From `flows.md`, Human Not Present, phase 2:

1. The agent selects open mandates.
2. The agent signs closed Checkout and Payment Mandates (`agent_sk`), binding `checkout_jwt` and `sd_hash`.
3. The Credential Provider verifies the payment mandates and may mint a token.
4. The agent sends the token and both checkout mandates to the merchant.
5. The merchant checks the closed checkout against the cart and the open constraints, then initiates payment.

KATA runs beside steps 3 and 5, after the agent has signed and before the Credential Provider or the merchant accepts the mandates. It consumes the verification result. It does not replace signature or constraint checking.

Human Present: evaluate after the Trusted Surface returns the user signatures and before token creation (`flows.md` Human Present payment steps). The user signed the closed values, so Q3 is "the user saw this cart," not "the cart is inside an open constraint set." Q4 still applies.

`specification.md` Dispute Evidence says the mandates and receipts can be replayed later. That trail is audit input to a past KATA decision. It is not a second authorization.

### What KATA consumes, what it adds, gaps

A verified open-mandate pair plus a closed pair that satisfies it is Q2 (user key or trusted agent-provider key on the open mandate; agent `cnf` on the closed signature) and Q3 (constraints versus `payment_amount`, `payee`, line items).

Q1 is the agent key in `cnf` and the header `kid`. The v0.2 sample has no `agent_id`, no `provider`, and no user `sub`. The worked example fills KATA-required `agent.provider` and `delegation.principal.id` with explicit gap markers, documented in the example README.

KATA adds the same layer as for VI: behavior (Q4), price integrity beyond the amount ceiling, seven decisions, `REVOKE`, `QUARANTINE`. AP2 receipts accept or reject a mandate. They do not score the agent.

**AP2 does not have:** quote, fee disclosed flags, peer price, delivered tier, per-agent spend baseline, or a decision ladder.

**KATA does not have:** SD-JWT presentation, Trusted Surface signing, PISP allowlists, instrument allowlists, or the merchant-signed checkout JWT. UCP remains the commerce action when the checkout object is UCP; see [examples/ucp-checkout/](../examples/ucp-checkout/) for that shape, with the sketch warning in its README.

**Worked example:** [examples/ap2-checkout/](../examples/ap2-checkout/), using the decoded Demo Merchant disclosures in `checkout_mandate.md` and `payment_mandate.md` at the v0.2 commit above.

## Agent identity (Q1 only)

These two do not carry a purchase intent or a KATA decision. They are identity evidence for question 1.

### Visa Trusted Agent Protocol

Sample at `16d59bd`. Not a separate specification document. The root README describes RFC 9421 HTTP Message Signatures so a merchant can check that a caller is a recognized agent, acting for a user, for a specific request. `tap-agent/README.md` lists signature components `@authority`, `@path`, `created`, `expires`, `nonce`, `keyId`, `tag`, and algorithms Ed25519 and RSA-PSS-SHA256.

`agent-registry/schemas.py` fields: agent `name`, `domain`, optional `description`, optional `contact_email`, `is_active` (`"true"` or `"false"` as strings); key `key_id`, `public_key`, `algorithm`, optional `description`, `is_active`. `AgentKeyFull.agent_id` is an integer on the stored key row.

| TAP | KATA Q1 |
|---|---|
| Registry agent identity + `domain` | `agent.agent_id`, `agent.name`. `domain` is the agent's domain, not a merchant counterparty. |
| `key_id`, `public_key`, `algorithm` | `agent.cryptographic_identity`, `agent.credentials[]` |
| `is_active` | Freshness of the credential. Not `delegation.status`. |
| Signature `nonce`, `created`, `expires` | Request-scoped. A weak join if stored as `session_id`. |
| Query-parameter consumer identifiers, PAR, loyalty, email, phone (root README) | Principal hints the merchant received. Not a VI/AP2 mandate, and not Q3 constraints. |

TAP does not define amount ranges, line items, or a decision. "Cryptographically verify agent intent" in the TAP README means the signature is bound to the domain and the operation. It is not a structured intent object.

### AGNTCY identity

Commit `8f7c1b5`, package `v1alpha1`. README: a unique id, ResolverMetadata, and Agent Badges as verifiable credentials (agent id, schema such as OASF, auth metadata). BYOID includes Okta, A2A Agent Cards, and W3C DIDs.

`id.proto` `ResolverMetadata`: `id`, `verification_method` (`id`, `public_key_jwk`), `service.service_endpoint`, `assertion_method`, `controller`.

`vc.proto` `BadgeClaims`: `id`, `badge`. `VerifiableCredential`: `context`, `type`, `issuer`, `content`, `id`, `issuance_date`, `expiration_date`, `credential_schema`, `credential_status`, and `Proof` `type` / `proof_purpose` / `proof_value`.

| AGNTCY | KATA Q1 |
|---|---|
| Resolver `id` | `agent.agent_id` |
| `verification_method.public_key_jwk` | `agent.cryptographic_identity` (`mechanism` `jwk`) |
| Badge VC `issuer`, dates, `credential_status` | `agent.credentials[]` |
| `controller` | A KATA `developer` or `provider` only when the deployment documents that meaning. The proto says the controller may change the metadata. It does not say "operator". |

No purchase constraints, no price fields, no seven-level decision.

## Shared rules

- Do not map an amount ceiling onto `price_expectation.quoted_price`.
- Do not emit `CHARGE_EXCEEDS_QUOTE` or `UNDISCLOSED_FEE` unless the source credential actually has a quote or a fee line.
- Do not emit `REVOKE` because a mandate verified. `REVOKE` is for the grant.
- A verified mandate with no behavior history is not a bare `ALLOW`. The worked examples use `ALLOW_WITH_MONITORING`, `reasons` `[]`, `required_action` `NONE`. Scores are illustrative. There is no calibrated model.
- KATA stays standards-neutral: another mandate format with the same evidence maps the same way.
