# Price Integrity Example

**Status: Concept / Open Design — not production ready.**

## Scenario

The same shopping agent as [`examples/shopping-agent/`](../shopping-agent/), with a tighter fact pattern than "under the ceiling."

The principal says:

> "Find and buy a laptop for me, maximum CAD 1,500. I was quoted CAD 1,000."

The agent is authenticated, the delegation is active, and the purchase is a **CAD 1,300 laptop**. That used to be the `ALLOW` row: CAD 1,300 is under CAD 1,500. The merchant is Techstore, the domain matches, and the settlement address matches the address on file. Reputation is fine.

The price is not fine.

| Fact | Value |
|---|---|
| Listed price | CAD 1,000 |
| Quoted price | CAD 1,000 |
| Intent tolerance | 1.15× the quote |
| Charged amount | CAD 1,300 (1.30×) |
| Fee the principal accepted | `tax`, `shipping` only |
| Fee on the charge | CAD 300 `service_fee`, `disclosed: false` |
| Agent's own typical spend | CAD 1,100 |
| Settlement | First attempt, still `pending` |

Identity, delegation, the ceiling, and the agent's own spend baseline all pass. The counterparty is who it claims to be. The charge still should not complete.

## Why this is not a hard equality check

1.30× sits in the overlap between honest price movement and overcharge. [AgentCommerceBench](https://github.com/BuildWithGordonAI/agentcommercebench) (Apache-2.0) reports that 14.6% of legitimate purchases exceed 1.15× the quoted price and 4.8% exceed 1.45×. The ratio alone is a reason to slow down. It is not a proof of fraud.

The undisclosed fee is the sharper signal. It is outside `fee_policy`. That is why the decision is `BLOCK` rather than `ALLOW_WITH_MONITORING`. The principal can still accept this specific charge (`required_action: HUMAN_APPROVAL`). Accepting it does not raise the CAD 1,500 ceiling and does not revoke the delegation. The merchant cheated; the grant is still good.

## What this example deliberately does not flag

**Honest retries.** About 20.3% of settlements in that benchmark fail with no adversary, and the retry uses a new idempotency key. A second attempt with `prior_attempt_status: failed` is that case. It is not `RETRY_FARMING`. Retry farming is a prior attempt that **settled**, was reported as failed, and is charged again. This request is attempt 1, status `pending`, so neither code applies.

**Silent downgrade.** `service.quoted_tier` is `standard`. `delivered_tier` is absent. `SERVICE_DOWNGRADE` must not fire without delivery evidence. The benchmark keeps that class as a control no wire-layer check should catch.

## Decision

→ **[`BLOCK`](../../schemas/decision.json)** — `risk_score: 76`, reasons `CHARGE_EXCEEDS_QUOTE`, `CHARGE_EXCEEDS_LISTED`, and `UNDISCLOSED_FEE`. Not `ACTION_EXCEEDS_INTENT`. Required action `HUMAN_APPROVAL`.

The score is illustrative. There is no calibrated model behind it.

## Files

- [`evaluate-request.json`](evaluate-request.json) — the `POST /kata/evaluate` payload
- [`evaluate-response.json`](evaluate-response.json) — the KATA decision
