# Payment Agent Example

**Status: Concept / Open Design — not production ready.**

## Scenario

A payment agent is delegated to pay recurring household bills, up to CAD 500 per transaction, from the principal's chequing account. Today it proposes a **CAD 640 transfer to a new payee** the principal has never paid before, and it is the third transfer in 20 minutes — well above the agent's usual velocity.

Nothing is forged: identity, delegation, and intent are all technically valid. But several weak signals combine:

| Signal | Observation |
|---|---|
| Amount | CAD 640 vs. CAD 500 ceiling — above limit |
| Payee | New payee, no history |
| Velocity | 3 transfers in 20 minutes vs. typical 1–2 per week |
| Behavior | Unusual tool sequence: payee added and paid within the same session |

No single signal is conclusive. Correlated across the risk graph, they justify escalation rather than an outright block.

## Decision

→ **[`STEP_UP`](../schemas/decision.json)** — `risk_score: 68`, reasons `AMOUNT_ABOVE_INTENT_CEILING`, `NEW_PAYEE`, and `UNUSUAL_AGENT_BEHAVIOR` (velocity + tool chaining), required action `HUMAN_APPROVAL`.

The payment is paused until the principal confirms — friction proportional to the risk, not a dead end.

## Files

- [`evaluate-request.json`](evaluate-request.json) — the `POST /kata/evaluate` payload
- [`evaluate-response.json`](evaluate-response.json) — the KATA decision
