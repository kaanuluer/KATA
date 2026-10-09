# AP2 Checkout — Worked KATA Evaluation

**Status: Concept / Open Design — not production ready.**

KATA is not affiliated with Google or the AP2 authors.

Inputs are the decoded disclosures in AP2 v0.2 `docs/ap2/checkout_mandate.md` and `docs/ap2/payment_mandate.md` at commit `e1ea56db72a6385bce3e5c1112b3a56ce60acb43`. Spec title: "Agentic Payment Protocol (v0.2)". Those files do not use the names Intent Mandate or Cart Mandate. The v0.1 names are mapped in [docs/interoperability.md](../../docs/interoperability.md).

[examples/ucp-checkout/](../ucp-checkout/) uses a simplified object (`mandate_type`, `shopping_intent.budget_limit`, `categories`). Those keys are a sketch. They are not in v0.1 `IntentMandate` and not in the v0.2 schemas.

## What the sample says

Open checkout `vct` `mandate.checkout.open.1`: `checkout.line_items` entry `line_1`, acceptable item `supershoe_limited_edition_gold_sneaker_womens_9_0` titled "SuperShoe Limited Edition Gold", quantity `1`; `checkout.allowed_merchants` id `merchant_1`, name "Demo Merchant", website `https://demo-merchant.example`. Header `kid` `agent-provider-key-1`. `cnf.jwk` is the P-256 key in the disclosure (`x` / `y` as printed). `iat` `1777342357`, `exp` `1777345957`.

Open payment `vct` `mandate.payment.open.1`: `payment.amount_range` currency `USD`, `max` `20000`, `min` `0`; the same payee; `payment.reference.conditional_transaction_id` `FzLoxbbtgQGYZxoSM2NJYJtkFTSsdfUBoVEQ12k7JN8`. Same `cnf`, `iat`, and `exp`.

Closed payment `vct` `mandate.payment.1`: `transaction_id` `NivWhuqfzcvZNapvIEJ2-3tsdQLkiuIcye2g46WVgX8`, payee `merchant_1`, `payment_amount.amount` `19900` USD, instrument `id` `stub`, `type` `card`, description "Card ••••4242". `iat` `1777342370`.

The closed checkout example embeds a checkout payload with `product.price` `199.0` and `total_price` `199.0`. `checkout_mandate.md` says that payload is outside the spec except when it is a UCP Checkout object. `types/item.json` instead defines `price` as an integer minor unit. This request copies `199.0` into `price.listed_price` as written. `19900` minor units become `action.amount` `199.00` per `types/amount.json`. There is no quoted price in the sample, so `quoted_price` is omitted. The prose `amount_range` example elsewhere in `payment_mandate.md` uses decimals (`100.50`); the disclosure used here uses the integer `20000`, which matches the schema.

`20000` minor units is the ceiling `maximum_amount` `200`. The charge is under that ceiling and matches the example list price. No fee lines are in the sample.

## KATA fills that are not AP2 claims

| KATA field | Value | Why |
|---|---|---|
| `agent.agent_id` | `agent-provider-key-1` | The sample has no agent id. This is the SD-JWT header `kid`. The `cnf.jwk` in the disclosure has no `kid` member. |
| `agent.provider` | `not-in-ap2-v0.2-sample` | [`schemas/agent.json`](../../schemas/agent.json) requires `provider`. v0.2 does not name one in this disclosure. |
| `delegation.principal.id` | `not-in-ap2-v0.2-sample` | The user signs via the Trusted Surface. This disclosure has no `sub`. `principal.type` `human` is a KATA enum. |
| `delegation.delegation_id` | the `conditional_transaction_id` | Stable binding of the open payment to the open checkout. AP2 does not name it `delegation_id`. |
| `intent.intent_id` | `kata-ap2-open-payment` | Assigned here. |
| `intent.purpose` | `purchase` | KATA label. |
| `intent.version` | `1` | KATA integer from the vct suffix `.1`. |
| `delegation.status` | `active` | KATA enum. The open mandate `exp` is after the closed payment `iat`. |

## Decision

`ALLOW_WITH_MONITORING`. Verified open constraints plus a closed payment inside them are Q2 and Q3 evidence. No behavior history is present, so this is not `ALLOW`. `reasons` is `[]`. `required_action` is `NONE`. `risk_score` `36` is illustrative.

Evaluate at AP2 Human Not Present phase 2, after the agent signs the closed mandates and before the Credential Provider or the merchant accepts them (`flows.md`). KATA does not verify the SD-JWT.

## Files

- [`source-mandates.json`](source-mandates.json) — decoded mandate objects from the spec examples. Not a KATA object.
- [`evaluate-request.json`](evaluate-request.json) — `POST /kata/evaluate`
- [`evaluate-response.json`](evaluate-response.json) — the decision
