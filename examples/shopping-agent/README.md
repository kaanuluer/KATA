# Shopping Agent Example

**Status: Concept / Open Design — not production ready.**

## Scenario

A user tells a shopping agent:

> "Find and buy a laptop for me, maximum CAD 1,500."

The agent is authenticated, holds a valid credential, and has purchase permission. It then attempts to purchase a **CAD 4,200 MacBook Pro** — nearly 3× the declared intent ceiling.

## Walkthrough

KATA evaluates the proposed action against all layers:

| Layer | Evaluation |
|---|---|
| Agent Identity | Valid — known agent, good reputation, no anomalies |
| Delegation | Valid — active, unexpired, shopping scope |
| Purchase Permission | Valid |
| **Intent** | **Max CAD 1,500** |
| **Observed Action** | **CAD 4,200** |
| Intent Match | ❌ **Failed** — `ACTION_EXCEEDS_INTENT` |

Identity and delegation are valid. The payment method is valid. But the action is inconsistent with the delegated intent, so:

```
Valid identity + valid authorization ≠ valid action
```

## Decision

→ **[`BLOCK`](../schemas/decision.json)** — `risk_score: 94`, reasons `ACTION_EXCEEDS_INTENT` and `DELEGATION_SCOPE_MISMATCH`, required action `HUMAN_APPROVAL`.

## Files

- [`evaluate-request.json`](evaluate-request.json) — the `POST /kata/evaluate` payload
- [`evaluate-response.json`](evaluate-response.json) — the KATA decision
