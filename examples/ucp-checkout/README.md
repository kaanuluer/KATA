# UCP Checkout — Worked KATA Evaluation

**Status: Concept / Open Design — not production ready.**

This example shows KATA evaluating a shopping agent on the **Universal Commerce Protocol (UCP)** against a **simplified** AP2-style grant. The JSON below is a sketch. `mandate_type`, `shopping_intent.budget_limit`, and `categories` are not fields in AP2 v0.1 `IntentMandate` and not fields in AP2 v0.2. The field-accurate v0.2 mapping is [docs/interoperability.md](../../docs/interoperability.md) and [examples/ap2-checkout/](../ap2-checkout/). The sketch still shows where KATA sits: the protocols supply the action and the grant; KATA makes the trust decision.

## The setup

1. **Principal** grants a human-not-present shopping limit, written here in sketch form (the v0.1 name was Intent Mandate; v0.2 uses open Checkout and Payment Mandates): *"Buy a bouquet of red roses under $40."* Machine-readable in this sketch: category `flowers`, budget limit $40.00, TTL 24h.
2. **Agent** discovers the merchant's capabilities via `/.well-known/ucp` and links identity via **OAuth 2.0** (UCP Identity Linking) — the delegation. Scope: `dev.ucp.shopping.checkout`.
3. **Agent** creates a UCP **checkout session**: 1× Bouquet of Red Roses at $42.00. Session status: `ready_for_complete`.
4. **KATA** evaluates the checkout *before* completion — the pre-execution evaluation point.

## The protocol objects (simplified)

**Sketch grant** (not an AP2 spec object):

```json
{
  "mandate_type": "intent_mandate",
  "mandate_id": "im_7d21",
  "payer": "usr_9182",
  "shopping_intent": {
    "categories": ["flowers"],
    "budget_limit": 40.00,
    "currency": "USD"
  },
  "prompt_playback": "Buy a bouquet of red roses under $40",
  "ttl": "2026-10-05T00:00:00Z"
}
```

**UCP checkout session** (action object):

```json
{
  "id": "cb9c0fc5-3e81-427c-ae54-83578294daf3",
  "status": "ready_for_complete",
  "line_items": [
    { "item": { "id": "bouquet_roses", "title": "Bouquet of Red Roses" }, "quantity": 1 }
  ],
  "currency": "USD",
  "totals": [{ "type": "total", "amount": 42.00 }]
}
```

## KATA evaluation

| Layer | Assessment |
|---|---|
| Agent identity | Valid — `UCP-Agent` profile header present, `request-signature` verifies |
| Delegation | Valid — OAuth identity linking, scope covers `dev.ucp.shopping.checkout`, unexpired |
| Intent | Max **$40.00** (Intent Mandate) |
| Observed action | **$42.00** checkout at `ready_for_complete` |
| Intent match | ❌ Failed — exceeds budget by $2.00 |

**Decision: `STEP_UP`** — the overage is small and possibly legitimate (tax, price drift), so KATA does not block outright. It requires human approval before the checkout completes. A larger deviation, or one paired with behavioral anomalies, would escalate to `BLOCK`.

A disclosed `tax` line inside the intent's `fee_policy` is the evidence that separates this from an undisclosed fee. The fields for that comparison, and a case that does block, are in [`examples/price-integrity/`](../price-integrity/). Equality between the mandate total and the checkout total is the wrong test: honest prices move.

## Why this example matters

- **UCP gives KATA a structured action to evaluate.** The checkout session — line items, totals, status — is machine-readable by design. `ready_for_complete` is a natural pre-execution hook.
- **A mandate can give KATA a structured intent.** Budget, category, and TTL in this sketch are the idea. The v0.2 objects that actually carry constraints are the open Checkout Mandate and open Payment Mandate, mapped in [docs/interoperability.md](../../docs/interoperability.md).
- **Neither protocol makes a risk decision.** AP2 captures authorization; UCP executes commerce. Neither measures intent-vs-action distance, profiles agent behavior, or issues graduated decisions. That missing layer is KATA.

## Files

- [`evaluate-request.json`](evaluate-request.json) — the `POST /kata/evaluate` payload: principal, agent (with UCP headers), delegation (OAuth identity linking), intent (AP2 Intent Mandate), action (UCP checkout session), context.
- [`evaluate-response.json`](evaluate-response.json) — the KATA decision: `STEP_UP`, risk score, reasons, required action.
