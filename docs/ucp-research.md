# UCP research

**Status: research note, plus one sandbox consumer.** The bureau does not host checkout. `POST /v1/sandbox/ucp/verify-checkout` and the MCP tool `verify_checkout` exist only when `GAB_ENV` is `sandbox`, and only for a `gab_test_` key.

Global Agent Bureau is an agent bureau and a technology company. The license is PolyForm Noncommercial 1.0.0. This note names one protocol, the pages opened for it, and what the bureau could consume later. It does not add a merchant profile or a checkout schema.

## Which UCP

This note means the **Universal Commerce Protocol** published at [ucp.dev](https://ucp.dev/), release **v2026-08-25**. It does not mean an older draft kept only for history, and it does not mean a different "UCP" abbreviation.

The announcements page lists earlier releases (v2026-01-11, v2026-01-23, v2026-04-08) and a lodging booking draft dated 25 September 2026. The pages below are the 25 August 2026 shopping release unless the URL says otherwise.

### Pages opened on 16 October 2026

- [Overview](https://ucp.dev/2026-08-25/specification/overview/)
- [Announcements](https://ucp.dev/documentation/announcements/)
- [Getting started](https://ucp.dev/2026-08-25/specification/getting-started/)
- [Checkout overview](https://ucp.dev/2026-08-25/specification/shopping/checkout/)
- [Checkout MCP binding](https://ucp.dev/2026-08-25/specification/shopping/checkout/mcp/)
- [Checkout A2A binding](https://ucp.dev/2026-08-25/specification/shopping/checkout/a2a/)
- [Signatures](https://ucp.dev/2026-08-25/specification/signatures/)
- [AP2 mandates extension](https://ucp.dev/2026-08-25/specification/payment/extensions/ap2-mandates/)
- [Reference](https://ucp.dev/2026-08-25/specification/reference/)
- Older overview, for the date contrast only: [v2026-01-23 overview](https://ucp.dev/2026-01-23/specification/overview/)

The January 2026 overview uses a server-selects version. The August 2026 overview separates protocol version selection from capability negotiation: the business advertises its current version, the platform picks one exact version, and the business then chooses the capabilities both sides advertise.

## What the specification says

A business publishes `/.well-known/ucp`. The profile carries `ucp.version`, `ucp.services`, and `ucp.payment_handlers` (required, even when empty) and optional `ucp.capabilities`. Names are reverse-domain strings such as `dev.ucp.shopping.checkout`.

Checkout is a shopping capability. The getting-started page describes REST operations under the business base URL: create a checkout session, read it, update it, and complete it. `UCP-Agent` is required on those requests. `Idempotency-Key` is required on create, update, and complete in that guide.

The checkout overview names four transport bindings: REST, MCP, A2A, and embedded. This note opened the MCP binding, the A2A binding, and the getting-started REST guide. The embedded binding page was not opened.

The MCP binding is streamable HTTP. Checkout operations are MCP tools: `create_checkout`, `get_checkout`, `update_checkout`, `complete_checkout`, and `cancel_checkout`. The binding says those operations are invoked with the JSON-RPC method `tools/call`. Every request carries `meta.ucp-agent.profile`. `complete_checkout` and `cancel_checkout` also require `meta.idempotency-key`.

The A2A binding puts the business endpoint on an Agent Card URL inside the UCP profile. Checkout state travels in an A2A message `DataPart` under `a2a.ucp.checkout`. Payment completion uses `a2a.ucp.checkout.payment`. Signals use `a2a.ucp.checkout.signals`. The extension URI in that binding is `https://ucp.dev/2026-08-25/specification/reference`.

Checkout `signals` are optional environment data from the platform. The checkout overview says signal values must not be buyer-asserted claims. Platforms supply them from direct observation or from an independently verifiable third-party attestation. Keys must be reverse-domain names. The worked examples on the overview use `dev.ucp.buyer_ip`, `dev.ucp.user_agent`, and a placeholder `com.example.risk_score`. `context` is a different object: provisional, not authoritative.

The overview schema note states that amounts are minor units.

The AP2 mandates extension is the capability `dev.ucp.common.payment.ap2_mandate`. It extends `dev.ucp.shopping.checkout` and is active only when both profiles advertise it. While it is active the business must put `ap2.merchant_authorization` on checkout responses and must refuse `complete_checkout` that lacks `ap2.checkout_mandate`. The extension page says AP2 v0.2 signs checkout JWTs with ECDSA (`ES256`, `ES384`, or `ES512`). Mandates are SD-JWT with key binding. The overview also shows a separate signing key for that extension (ECDSA P-256) beside an Ed25519 key used for HTTP transport identity.

`docs/interoperability.md` in this repository already records a read of the AP2 v0.2 specification at commit `e1ea56db72a6385bce3e5c1112b3a56ce60acb43`. That page was not re-fetched for this note. It says AP2 and Verifiable Intent amounts are integer minor units, while KATA amounts are major units.

`examples/ucp-checkout/README.md` says its grant JSON is a sketch. The property names there are not AP2 v0.1 or v0.2 fields.

## What the bureau could consume

The bureau checks an agent before a payment. It does not host a merchant checkout, a catalog, or a payment handler.

A UCP checkout object that a platform or merchant already holds can be the action passed to the existing verify route: agent, amount, currency, and merchant. The bureau answer stays ALLOW, DENY, or STEP_UP. Completing the UCP session stays with the business. Minor units in the checkout have to be converted to the major units KATA stores before that check. `docs/interoperability.md` already states that conversion for AP2.

When `dev.ucp.common.payment.ap2_mandate` is active, the checkout is a signed agreement. The bureau should see it only after the signature check the extension requires. An unverified mandate is missing evidence, not a grant. That is the same position `docs/interoperability.md` takes for AP2 and Verifiable Intent.

Checkout `signals` are the slot a platform can use for outside evidence. A signed bureau result could ride there only as a third-party attestation the platform relays, under a reverse-domain key. None of the pages opened assign a key to Global Agent Bureau. `com.example.risk_score` in the overview is an example, not a bureau field.

The MCP binding and a bureau MCP server are different tool lists. UCP's tools create and complete a checkout. A bureau tool list reads and checks an agent. A shopping agent can use the merchant's UCP endpoint for the cart and a bureau endpoint for the check. This note does not merge those lists.

## Sandbox consumer

`POST /v1/sandbox/ucp/verify-checkout` and the MCP tool `verify_checkout` are the first bureau consumer. A merchant or an institution submits a checkout it already holds. The bureau checks that object against the stored intent agreement, the stored agent score, and revocation status. The answer is `ALLOW`, `STEP_UP`, or `DENY`. Completing the session stays with the business.

`signals` are not evidence. A buyer-asserted signal is `DENY`. `context` stays provisional and is not the amount. `ap2.checkout_mandate` is not a grant. Amounts stay minor units until the assumed scale converts them. The path `totals` with `type` `total`, the `currency` path, and the currency scale table are assumed. They are marked assumed on the response. `com.example.risk_score` is ignored. The response `compatibility_claim` is `none`.

## What the bureau should not expose

A `/.well-known/ucp` business profile, checkout-session routes, payment handlers, and `create_checkout` would make the bureau a merchant endpoint. The specification's business role owns totals, fulfillment, and completion. That is not an agent-bureau role.

Identity linking appears in overview examples as `dev.ucp.common.identity_linking` with a spec URL. That identity-linking page was not opened. This note does not describe its flow.

## Effort and risk

| Direction | Effort | Risk |
| --- | --- | --- |
| Leave UCP unimplemented | None beyond this note | No protocol surface to drift |
| Map a checkout object into the existing verify route | A translator and tests. The verify route already exists | Minor-unit amounts written as major units. Buyer `context` treated as a fact. An unverified mandate treated as a grant |
| Relay a signed bureau result inside `signals` | A reverse-domain key, a small signed object, and a platform willing to attach it | No key for this bureau was found. Merchants may ignore an unknown key. The platform, not the buyer, has to attach it |
| Host checkout, REST, MCP checkout tools, or an A2A business agent | Profile negotiation, signatures (RFC 9421 on the signature page), idempotency, payment handlers, and fulfillment | The bureau would be taking a merchant job. Payment and tax behavior are outside the current API |

The A2A **binding** on ucp.dev was opened. The Agent2Agent protocol specification that defines `message/send`, Agent Card, and `DataPart` was not opened. Where this note describes A2A, it describes only the UCP binding page.

The AP2 GitHub specification was not opened again for this note. Statements about AP2 v0.2 field names and the minor-unit rule come from `docs/interoperability.md` in this repository. Statements about how UCP turns that protocol on come from the AP2 mandates extension page opened above.

## Verified

- The protocol in this note is Universal Commerce Protocol **v2026-08-25**, from the URLs listed above, read on 16 October 2026.
- Discovery document is `/.well-known/ucp`. `version`, `services`, and `payment_handlers` are required on both business and platform profiles in the August overview.
- Checkout REST, as the getting-started page describes it, uses checkout sessions, `UCP-Agent`, and `Idempotency-Key` on the operations that guide implements.
- The MCP binding lists `create_checkout`, `get_checkout`, `update_checkout`, `complete_checkout`, and `cancel_checkout`, invoked with `tools/call`, on streamable HTTP.
- The A2A binding uses an Agent Card URL, `a2a.ucp.checkout`, `a2a.ucp.checkout.payment`, and `a2a.ucp.checkout.signals`.
- Checkout `signals` must not be buyer-asserted. Keys are reverse-domain. Third-party attestations are allowed when the platform relays them.
- `context` is provisional. Amounts in the overview schema note are minor units.
- `dev.ucp.common.payment.ap2_mandate` is the UCP capability that turns on AP2 mandates. It is inactive unless both sides advertise it. The extension page requires `ap2.merchant_authorization` on responses and `ap2.checkout_mandate` on completion.
- The extension page says AP2 v0.2 checkout JWTs use ECDSA (`ES256`, `ES384`, or `ES512`).
- `examples/ucp-checkout/` is labeled a sketch in its README. `docs/interoperability.md` says KATA amounts are major units.
- No page opened here names a Universal Commerce Protocol signal or capability for Global Agent Bureau.

## Assumed

- The useful bureau role is to **consume** a checkout as an action to verify, not to host checkout. The specification does not assign that role. It is a product judgment from the tool lists above.
- A shopping agent would keep the merchant UCP endpoint and a bureau endpoint as two clients. Nothing in the UCP specification requires or forbids that split.
- A future reverse-domain signal could carry a signed bureau result. No such key was found, and no merchant was seen accepting one.
- The A2A binding's `message/send` and Agent Card fields match the current Agent2Agent specification. That specification was not opened.
- AP2 v0.2 field-level mapping in `docs/interoperability.md` still matches the GitHub specification at the cited commit. That repository was not opened again for this note.
- Hosting a UCP business would be a large detour. That is a judgment about scope, not a sentence in the specification.
