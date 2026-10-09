# KATA Risk Model

**Status: Concept / Open Design — not production ready.**

This document describes how KATA composes risk: what the component risks are, how they are correlated rather than scored in isolation, and what an explainable decision must contain.

## Core principle: correlation, not isolation

The foundational insight KATA borrows from fraud research:

> **Risk signals should be correlated rather than evaluated independently.**

```
Signal → Score              ❌  (traditional, isolated)
Identity + Delegation + Intent + Behavior + Action + Context
        ↓
Connected Risk Graph
        ↓
Decision                    ✅  (KATA)
```

A single signal may be benign. The *combination* of weak signals across the graph — an unusual infrastructure change *plus* a slight intent deviation *plus* elevated action velocity — is what indicates risk.

**The linkage principle.** Every evaluation should join to history on each identifier: how many principals has this agent served? How many delegations has this principal granted? How many counterparties has this agent paid? Linkage counts plus recency are the cheapest, most decisive features in fraud models — KATA treats them as first-class context in the graph.

## Component risks

| Component | What is assessed |
|---|---|
| **Identity risk** | How confident are we in who this agent is? Covers identifier validity, cryptographic proof, provider/model reputation, deployment environment, infrastructure reputation, security posture. |
| **Delegation risk** | How valid is the authority? Covers delegation existence, freshness, expiry, revocation status, whether the delegation chain (agent-to-agent) is intact, and whether the delegation was granted under suspicious circumstances. |
| **Intent risk** | How clear and constraining is the intent? Ambiguous, missing, or over-broad intent is itself a risk — it leaves room for the agent to "interpret" its way into trouble. |
| **Behavior risk** | How consistent is current behavior with the agent's profile and the task at hand? Unusual tool usage, abnormal API sequences, unexpected scope expansion, privilege escalation attempts, velocity anomalies. Retry *cadence* belongs here. A retry after a failed settlement does not — see price integrity below. |
| **Action risk** | How risky is *this specific action* in context? Amount, irreversibility, data sensitivity, privilege level, and whether the quote, the list, the fees, and the counterparty agree. Evaluated pre-execution. |
| **Transaction risk** | How risky is the resulting transaction given everything above? The traditional fraud-risk layer, extended into the agentic graph — including a genuine counterparty whose charge does not match its own price. |

## Score composition (conceptual)

```
Agent Identity Risk
+ Delegation Risk
+ Intent Risk
+ Behavior Risk
+ Action Risk
+ Transaction Risk
=
KATA Risk Score
```

Important caveats, per the framework:

1. **The score is not the decision.** Policy maps the score *and its composition* to one of the seven decisions. Two actions with the same score but different risk composition (e.g., identity risk vs. intent risk) may — and should — get different decisions.
2. **Composition matters more than the total.** A high intent-risk component (action far from declared intent) should weigh differently than diffuse low-level behavioral noise.
3. **Missing evidence is a signal.** If identity cannot be verified or intent is absent, that increases risk rather than being treated as neutral.

## Cost discipline: tiered evaluation

Not every signal needs to run on every evaluation. Following fraud-orchestration practice:

- **Cheap signals on every event** — delegation validity, hard intent limits, quote against charge, disclosed-fee check, geolocation, line type. Milliseconds, near-zero cost.
- **Passive signals continuously** — behavioral profiles, reputation, velocity counters. Collected in the background, consulted on every decision.
- **Expensive signals at step-up only** — identity re-verification, SIM-swap queries, deep reputation lookups, human approval. High friction, high cost, reserved for elevated risk.

The architecture follows the cost curve: the fast path stays fast, and depth is spent where risk justifies it. See [docs/architecture.md](docs/architecture.md).

## Price integrity and the counterparty

Identity, delegation, and a user ceiling can all pass while the charge is still wrong. The component that moves is action risk and transaction risk, not identity risk. The delegation is not the thing that failed.

Compare prices with a **band**, not with equality. [AgentCommerceBench](https://github.com/BuildWithGordonAI/agentcommercebench) (Apache-2.0) reports that 14.6% of legitimate purchases exceed 1.15× the quoted price and 4.8% exceed 1.45×. Its overcharge class is drawn from a range that overlaps that tail, so a threshold sitting in the empty space between "honest" and "attack" would detect perfectly and measure nothing — there is no such space. `tolerance_ratio` on the intent is the band *this principal* declared. A ratio inside the overlap is a reason to slow down, not a proof of fraud.

The same ladder applies. Illustrative, not calibrated:

| What the evidence shows | Decision |
|---|---|
| Charge inside the declared band, fees disclosed, settlement address matches the merchant on file | `ALLOW` |
| Charge in the honest-movement tail, or counterparty risk elevated, with no contradictory fee | `ALLOW_WITH_MONITORING` |
| The gap might be tax, FX, or a fee the intent did not itemize | `STEP_UP` |
| Outside the declared band, agent and grant otherwise valid, principal can still accept the price | `HUMAN_APPROVAL` |
| Undisclosed fee, drip far outside the band, or retry farming (prior attempt **settled**, then reported failed) | `BLOCK` |
| The agent keeps paying a counterparty after price-integrity blocks, and will not stop | `QUARANTINE` |

`REVOKE` stays for a grant that should not exist. A cheating merchant does not, by itself, revoke the agent.

**Honest retries are not fraud.** The same benchmark measures about 20.3% of settlements failing with no adversary, and retries mint new idempotency keys. `prior_attempt_status: failed` plus a new key is that case. `RETRY_FARMING` requires the prior attempt to have **settled**. The benchmark scores no-adversary failures in their own bucket: noticing that money was lost can be useful, and it is not an attack label. Do not emit `RETRY_FARMING` for them.

**Relative baselines complement `maximum_amount`.** Each agent's typical spend is its own scale: the same amount is over-limit for one agent and unremarkable for another. Carry that as `agent_spend_baseline`. Do not use it as the listed price. A merchant who overcharges one agent on every order has already written that price into the baseline.

**`SERVICE_DOWNGRADE` needs delivery evidence.** Quoted tier versus delivered tier can be recorded. If `delivered_tier` is absent, the code does not fire. Missing fulfillment is missing evidence.

**`PRICE_DISCRIMINATION` needs peers.** `peer_price` is an external reference. The buyer's own history is the wrong baseline.

## Reason codes

A shared taxonomy is still open. The draft codes below are the ones examples and schemas use. They explain a decision. They are not a detector, and they are not a closed enum — `decision.reasons` stays a list of strings.

| Code | Fires when | Does not fire when |
|---|---|---|
| `ACTION_EXCEEDS_INTENT` | The action breaks a declared intent limit (amount, category, time, verb). | The amount is under the ceiling. |
| `DELEGATION_SCOPE_MISMATCH` | The action is outside the delegation's scope. | The grant covers this verb and ceiling. |
| `AMOUNT_ABOVE_INTENT_CEILING` | Amount is over `maximum_amount` but other scope still matches. | The overage is a fee story rather than the ceiling. Use a price code. |
| `NEW_PAYEE` | The payee has no history with this principal. | The merchant is known and the settlement address matches. |
| `UNUSUAL_AGENT_BEHAVIOR` | Tool use, velocity, or scope diverges from the agent's profile. | The only oddity is the merchant's price. |
| `CHARGE_EXCEEDS_QUOTE` | `charged_amount` / `quoted_price` is outside `tolerance_ratio`. | The charge is inside the band. Movement inside the band is ordinary. |
| `CHARGE_EXCEEDS_LISTED` | The charge is outside the band above `listed_price` or `expected_price`. | List and charge agree within the band. |
| `UNDISCLOSED_FEE` | A `fee_breakdown` line has `disclosed: false` and is outside `fee_policy`. | The line's code is in `allowed_codes`, or it was disclosed. |
| `SERVICE_DOWNGRADE` | Delivery evidence shows a cheaper tier than `quoted_tier` at full price. | `delivered_tier` is absent. |
| `RETRY_FARMING` | A new charge follows an attempt whose status is `settled`. | The prior attempt `failed`. That is the common no-adversary case. |
| `PRICE_DISCRIMINATION` | The charge is outside the band above `peer_price`. | The only reference is this buyer's own baseline. |

Worked combination: [`examples/price-integrity/`](../examples/price-integrity/) uses `CHARGE_EXCEEDS_QUOTE`, `CHARGE_EXCEEDS_LISTED`, and `UNDISCLOSED_FEE`. The ceiling holds, so `ACTION_EXCEEDS_INTENT` is absent. The decision is `BLOCK` because the fee policy is broken; `required_action` is `HUMAN_APPROVAL`, so the principal can still accept that charge. The ratio alone (1.30×, inside the overlap the benchmark describes) would not be enough to call it proved fraud.

## Explainability requirements

A KATA decision must never be a bare number. Every decision should include:

- **Risk score** — the composed numeric assessment (0–100 scale suggested; not yet fixed).
- **Risk factors** — which component risks contributed and how.
- **Policy violations** — which specific policies were triggered.
- **Intent mismatch** — where applicable, the measured distance between declared intent and observed action, including quote, list, and fees when those fields are present.
- **Behavioral anomalies** — which behavioral signals fired.
- **Required remediation** — what must happen next (`required_action`: e.g., `HUMAN_APPROVAL`, re-verification, or revocation steps).

## Continuous re-evaluation

Risk is not computed once at session start. The graph must be re-evaluated when:

- The agent's behavior changes (new tool patterns, velocity shifts).
- The delegation's scope or validity changes (expiry approaching, revocation events).
- The agent's infrastructure changes (new deployment environment, network path).
- The declared intent becomes unclear or is updated.
- The observed action deviates from authorization.
- New risk intelligence arrives (reputation changes, threat feeds).

Trust is **dynamic**: an agent trusted five minutes ago may become untrusted. Re-evaluation can tighten *or loosen* trust — consistent behavior over time should reduce friction, not just accumulate suspicion.

## Open questions for the risk model

- Exact scoring math and calibration (additive vs. weighted vs. learned models).
- How much historical behavior should influence current trust (recency vs. depth).
- Standardized reason codes. A draft list, including the price-integrity codes, is in the table above. Interoperability still needs that list to settle.
- How wide a price-tolerance band should be. The benchmark shows honest movement and overcharge overlap; KATA does not pick 1.15× or 1.45× as a threshold.
- Who supplies `peer_price` and delivery evidence. Without them, `PRICE_DISCRIMINATION` and `SERVICE_DOWNGRADE` stay silent.
- How decisions and scores are exchanged between institutions without leaking sensitive behavioral data.
