# Fraud Signals: Traditional → Agentic Mapping

**Status: Concept / Open Design — not production ready.**

KATA's core design principle:

> **KATA should extend fraud intelligence into the agentic world rather than create a completely isolated fraud model.**

Decades of fraud-prevention knowledge don't become obsolete when agents enter the picture — they get translated. This document expands the mapping from the framework into twelve signal pairs, each with what the agentic equivalent means in practice.

## The mapping

### 1. User identity → Principal identity

The human (or business, institution, system) ultimately responsible for the delegation. Verifying the principal anchors the entire trust graph — every delegation, intent, and approval traces back here.

### 2. Device identity → Agent identity

Just as fraud systems fingerprint devices, KATA fingerprints agents: identifier, provider, model, version, deployment environment, and cryptographic identity. The agent is the "device" of the agentic world.

### 3. Device reputation → Agent reputation

A device with a history of fraud is risky; so is an agent with a history of blocked or anomalous actions. Reputation accumulates from decision history across sessions and, eventually, across principals.

### 4. IP reputation → Agent infrastructure reputation

Fraud systems score IPs and networks. KATA scores the infrastructure the agent runs on: hosting provider, ASN, network path, TLS posture, and whether the environment changed unexpectedly mid-session.

### 5. Behavioral biometrics → Agent behavioral profile

Keystroke dynamics and mouse movements become tool-usage patterns, API call sequences, retry behavior, and action velocity. The question is the same: *does this behave like the legitimate actor?*

### 6. Account linkage → Principal-agent-entity graph

Fraud rings are found through shared devices, IPs, and accounts. In agentic systems, the graph connects principals, agents, sub-agents, merchants, and counterparties — revealing, for example, one principal controlling many agents, or one agent serving suspiciously many principals.

### 7. Transaction velocity → Agent action velocity

Card-testing attacks show up as velocity spikes; so do compromised agents probing capabilities. Unusual action velocity — transfers per minute, API calls per session — is a first-order behavioral signal.

### 8. Authentication → Delegation verification

"Is this user authenticated?" becomes "Is this delegation real, fresh, unexpired, and unrevoked?" Authentication proves *who*; delegation verification proves *who authorized whom, to do what*.

### 9. Authorization → Scope / intent verification

Traditional authorization checks a permission bit. KATA checks the permission *against the declared intent*: the agent may be allowed to purchase, but was it allowed to purchase *this*, for *this much*, *now*?

### 10. Transaction risk → Intent / action risk

The transaction is still scored — amount, merchant, irreversibility — but now it's scored as the *output of an intent-action comparison*. A legitimate-looking transaction can still be high-risk if it contradicts intent.

### 11. Session risk → Agent session risk

Session hijacking, session anomalies, and session age have direct analogues: agent sessions can be hijacked, can drift in behavior over time, and accumulate trust that an attacker would love to inherit.

### 12. Merchant risk → Agent / merchant interaction risk

Fraud systems score merchants; KATA scores the *relationship* — is this agent interacting with merchants inside or outside its intent constraints? A shopping agent suddenly paying an unknown offshore merchant is the agentic version of a card being used at a high-risk MCC.

## The correlation principle

The mapping above is only useful if the signals are **correlated, not scored in isolation**:

```
Signal → Score                                          ❌
Identity + Delegation + Intent + Behavior + Action + Context
        ↓
Connected Risk Graph
        ↓
Decision                                                ✅
```

Inspiration for this principle comes from fraud-risk-signal research emphasizing that risk signals should be correlated rather than evaluated independently — for example, the "Fraud Risk Signals" analysis at https://priyacali.github.io/fraud-risk-signals-article/. KATA extends that principle into agentic systems: a single signal rarely indicates fraud, but multiple connected signals across the graph do.

## Using this mapping

- **For fraud practitioners:** this is the on-ramp. Your existing signal taxonomy maps almost 1:1 — the mental models transfer.
- **For agent builders:** these are the signals your agents will be judged on. Design for observability: structured intents, attributable actions, stable identities.
- **For the framework:** each pair is a work item — defining exactly how the agentic equivalent is measured, exchanged, and standardized.
