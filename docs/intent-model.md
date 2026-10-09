# KATA Intent Model

**Status: Concept / Open Design — not production ready.**

Intent is one of KATA's most important concepts: the principal's *declared purpose* for the delegation, expressed as structured, machine-readable data, and used as a first-class risk signal throughout the agent's session.

## Why structured intent

Natural-language instructions are ambiguous. "Buy me a laptop" leaves open the price, the brand, the merchant, the deadline — and every gap is room for the agent to drift, misinterpret, or be manipulated. KATA's position:

> **Intent should become a first-class risk signal.**

Structured intent turns "what did the human mean?" into something measurable: the **distance between declared intent and observed action**. Without structure, intent verification is guesswork; with it, it's a computation.

## Proposed intent fields

| Field | Type | Description |
|---|---|---|
| `intent_id` | string | Unique identifier for this intent declaration. |
| `purpose` | string | High-level purpose: `purchase`, `transfer`, `booking`, `data_access`, `communication`, etc. |
| `category` | string | Domain category, e.g. `electronics`, `travel`, `groceries`. |
| `maximum_amount` | number | Hard spending ceiling for the intent (in `currency`). |
| `currency` | string | ISO 4217 currency code, e.g. `CAD`. |
| `merchant_constraints` | array | Allowed / blocked merchants or merchant categories. Empty = no constraint. |
| `price_expectation` | object | Optional quote and list anchors (`quoted_price`, `listed_price`) and a `tolerance_ratio`. A charge under `maximum_amount` can still disagree with the quote. |
| `fee_policy` | object | Fees the principal has already accepted (`allowed_codes`, `allow_undisclosed`). |
| `counterparty_constraints` | object | Who may be paid: merchant ids, settlement addresses, maximum counterparty risk. Complements `merchant_constraints`. |
| `time_limit` | string (datetime) | The intent expires after this timestamp. |
| `allowed_actions` | array of strings | Verbs the agent may perform under this intent: `search`, `compare`, `purchase`, `cancel`, etc. |
| `constraints` | object | Additional key-value limits (e.g., `{"max_items": 1, "shipping": "standard"}`). |
| `natural_language_source` | string | The original human instruction, preserved for audit and explainability. |
| `version` | integer | Intent version; increments when the principal updates the intent. |

Conceptual example:

```json
{
  "intent_id": "int_9f31",
  "purpose": "purchase",
  "category": "electronics",
  "maximum_amount": 1500,
  "currency": "CAD",
  "merchant_constraints": [],
  "time_limit": "2026-10-10T23:59:59Z",
  "allowed_actions": ["search", "compare", "purchase"],
  "constraints": { "max_items": 1 },
  "natural_language_source": "Find and buy a laptop for me, maximum CAD 1,500.",
  "version": 1
}
```

The normative schema draft is [`schemas/intent.json`](../schemas/intent.json). Observed price, fees, settlement, and the counterparty live on the action — [`schemas/action.json`](../schemas/action.json) — because they are facts about the charge, not about the grant.

## Price integrity

`maximum_amount` answers "is this under the ceiling the principal set?" It does not answer "is this the price that was quoted?"

> You tell an agent: **"Find and buy a laptop for me, maximum CAD 1,500."** The agent buys a CAD 1,300 laptop. The ceiling holds. The merchant had listed and quoted that laptop at CAD 1,000.

Identity, delegation, and intent can all be valid while value still leaves. The party taking the extra is the counterparty, not a forged agent. KATA's draft separates three comparisons:

| Comparison | Fields | What a mismatch means |
|---|---|---|
| Ceiling | `maximum_amount` vs. `amount` | The agent went past the grant. |
| Quote and list | `price_expectation` vs. action `price.quoted_price`, `listed_price`, `charged_amount` | The charge moved off the price the principal was shown. |
| Fees | `fee_policy` vs. `price.fee_breakdown` | A line was added that the principal had not accepted. |

**Do not test quote equality.** Honest prices move. [AgentCommerceBench](https://github.com/BuildWithGordonAI/agentcommercebench) (BuildWithGordonAI, Apache-2.0) reports that 14.6% of legitimate purchases exceed 1.15× the quoted price and 4.8% exceed 1.45×, and its overcharge class overlaps that tail on purpose. A cut placed in a gap between "honest" and "attack" would measure nothing, because that gap is not there. `tolerance_ratio` is a band the principal declared for *this* intent. It is not a universal fraud line.

**A per-agent spend baseline complements the ceiling. It does not replace it.** The same benchmark builds each agent's limit as a multiple of that agent's own typical spend, so one amount is over-limit for one agent and ordinary for another. The action may carry `agent_spend_baseline` for that relative check. A charge inside both the user's ceiling and the agent's own baseline can still be an overcharge against the list price.

The counterparty block on the action (`merchant_id`, domain, `settlement_address` against `registered_settlement_address`, reputation and risk) is how KATA records *who is paid*. A matching settlement address is evidence the payee is the merchant it claims to be. It is not evidence the price is fair.

Worked case: [`examples/price-integrity/`](../examples/price-integrity/).

## Intent capture UX (concept)

The hardest design problem: turning natural language into structured intent without burdening the principal.

1. **Parse.** The agent (or the KATA layer) proposes a structured intent from the human's instruction.
2. **Confirm.** For anything consequential (money, data, commitments), the principal reviews and confirms the key limits — amount, scope, deadline — in plain language. *"So: one laptop, max CAD 1,500, by Oct 10. Right?"*
3. **Sign.** The confirmed intent is recorded immutably (signed, versioned) so later tampering is detectable.
4. **Default tight.** When intent is ambiguous, KATA should prefer narrower scope and escalate (`STEP_UP` / `HUMAN_APPROVAL`) rather than assume.

## Intent drift detection (concept)

Intent drift is the gradual divergence of actions from the original intent — often without any single action being egregious:

```
Declared intent:  "laptop, max CAD 1,500"
Action 1:         search laptops CAD 1,200–1,600      → minor deviation, note
Action 2:         compare models up to CAD 2,000      → drift signal
Action 3:         attempt purchase CAD 4,200          → BLOCK (ACTION_EXCEEDS_INTENT)
```

Detection approach:

- **Per-action distance.** Each action is scored against the intent fields (amount over limit, quote or list outside `tolerance_ratio`, fee outside `fee_policy`, disallowed merchant or settlement address, expired time window, action verb not in `allowed_actions`).
- **Cumulative drift.** A running measure of how far the session has moved from intent. Small deviations accumulate; the trend can trigger escalation before any single action crosses a hard line.
- **Re-baselining requires the principal.** If the principal genuinely changes their mind, intent must be *explicitly re-declared* (new version) — the agent must never silently widen its own mandate.

## Versioning

- Intents are **immutable once confirmed**; changes create a new version.
- The full version history is retained for audit.
- Evaluations always reference the intent version in force at the time of the action.
- Revocation of a delegation invalidates all intents bound to it.

## Examples

See [`examples/shopping-agent/`](../examples/shopping-agent/) for a worked ceiling mismatch, [`examples/price-integrity/`](../examples/price-integrity/) for a charge under the ceiling that still fails the quote, and [`schemas/intent.json`](../schemas/intent.json) for the schema draft.
