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
| **Behavior risk** | How consistent is current behavior with the agent's profile and the task at hand? Unusual tool usage, abnormal API sequences, excessive retries, unexpected scope expansion, privilege escalation attempts, velocity anomalies. |
| **Action risk** | How risky is *this specific action* in context? Amount, irreversibility, data sensitivity, privilege level, merchant/counterparty risk. Evaluated pre-execution. |
| **Transaction risk** | How risky is the resulting transaction given everything above? The traditional fraud-risk layer, extended into the agentic graph. |

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

- **Cheap signals on every event** — delegation validity, hard intent limits, geolocation, line type. Milliseconds, near-zero cost.
- **Passive signals continuously** — behavioral profiles, reputation, velocity counters. Collected in the background, consulted on every decision.
- **Expensive signals at step-up only** — identity re-verification, SIM-swap queries, deep reputation lookups, human approval. High friction, high cost, reserved for elevated risk.

The architecture follows the cost curve: the fast path stays fast, and depth is spent where risk justifies it. See [docs/architecture.md](docs/architecture.md).

## Explainability requirements

A KATA decision must never be a bare number. Every decision should include:

- **Risk score** — the composed numeric assessment (0–100 scale suggested; not yet fixed).
- **Risk factors** — which component risks contributed and how.
- **Policy violations** — which specific policies were triggered.
- **Intent mismatch** — where applicable, the measured distance between declared intent and observed action.
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
- Standardized reason codes (e.g., `ACTION_EXCEEDS_INTENT`) — a shared taxonomy is needed before interoperability is possible.
- How decisions and scores are exchanged between institutions without leaking sensitive behavioral data.
