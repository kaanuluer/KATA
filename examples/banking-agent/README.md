# Banking Agent Example

**Status: Concept / Open Design — not production ready.**

## Scenario

The same shopping agent from the [shopping-agent example](../shopping-agent/) — delegated to buy a laptop, max CAD 1,500 — selects a compliant CAD 1,300 laptop and then **suddenly attempts to access the user's investment account** to "check available funds."

The identity is still valid. The agent is still legitimate. The delegation is still active. But:

```
Delegated Scope ≠ Requested Action
```

The requested action (`data_access` on an investment account) is not in the delegation's `allowed_action_verbs`, is not covered by the declared intent (`purpose: purchase`, `category: electronics`), and represents a sudden privilege/scope expansion — a classic behavioral red flag.

## Walkthrough

| Layer | Evaluation |
|---|---|
| Agent Identity | Valid — same known agent |
| Delegation | Valid — but scope covers `search`, `compare`, `purchase` only |
| Intent | Purchase of electronics, max CAD 1,500 |
| **Observed Action** | **`data_access` on investment account `****7788`** |
| Scope Match | ❌ **Failed** — `DELEGATION_SCOPE_MISMATCH` |
| Behavior | ❌ Unexpected scope expansion — `UNUSUAL_AGENT_BEHAVIOR` |

This is exactly the case where "an authorized agent is not automatically authorized for every action." The delegation was shopping; the action is banking.

## Decision

→ **[`BLOCK`](../schemas/decision.json)** — `risk_score: 89`, reasons `DELEGATION_SCOPE_MISMATCH` and `UNUSUAL_AGENT_BEHAVIOR`, required action `HUMAN_APPROVAL`.

If the principal genuinely wants the agent to see the investment account, that requires a **new delegation with explicit scope** — the agent must never widen its own mandate.

## Files

- [`evaluate-request.json`](evaluate-request.json) — the `POST /kata/evaluate` payload
- [`evaluate-response.json`](evaluate-response.json) — the KATA decision
