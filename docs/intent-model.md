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

The normative schema draft is [`schemas/intent.json`](../schemas/intent.json).

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

- **Per-action distance.** Each action is scored against the intent fields (amount over limit, disallowed merchant, expired time window, action verb not in `allowed_actions`).
- **Cumulative drift.** A running measure of how far the session has moved from intent. Small deviations accumulate; the trend can trigger escalation before any single action crosses a hard line.
- **Re-baselining requires the principal.** If the principal genuinely changes their mind, intent must be *explicitly re-declared* (new version) — the agent must never silently widen its own mandate.

## Versioning

- Intents are **immutable once confirmed**; changes create a new version.
- The full version history is retained for audit.
- Evaluations always reference the intent version in force at the time of the action.
- Revocation of a delegation invalidates all intents bound to it.

## Examples

See [`examples/shopping-agent/`](../examples/shopping-agent/) for a worked intent-mismatch evaluation, and [`schemas/intent.json`](../schemas/intent.json) for the schema draft.
