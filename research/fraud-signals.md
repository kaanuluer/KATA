# Fraud Signals: Traditional → Agentic Mapping

**Status: Concept / Open Design — not production ready.**

KATA's core design principle:

> **KATA should extend fraud intelligence into the agentic world rather than create a completely isolated fraud model.**

Decades of fraud-prevention knowledge don't become obsolete when agents enter the picture — they get translated. This document expands the mapping from the framework into twelve signal pairs, then examines how agentic AI shifts the strength of each underlying variable.

Primary reference: **"From Cookie IDs to Agentic AI: Have Fun with Fraud Variables"** (Priyanka Aggarwal, October 2026) — https://priyacali.github.io/fraud-risk-signals-article/

## Terminology

Following the reference article's usage:

- A **variable** is any fraud-risk intelligence input (IP, device, email, …).
- An **identifier** is a data element the user presents or the system collects (a phone number, an IP address).
- A **signal** is derived from identifiers or context (a datacenter IP that changed five minutes ago).
- A **verdict** is what a policy, score, or model returns.

KATA's object model mirrors this: identifiers and context feed **RiskSignals**, which the risk engine correlates into a **Decision** (the verdict).

## The mapping

### 1. User identity → Principal identity

The human (or business, institution, system) ultimately responsible for the delegation. Verifying the principal anchors the entire trust graph — every delegation, intent, and approval traces back here.

### 2. Device identity → Agent identity

Just as fraud systems fingerprint devices, KATA fingerprints agents: identifier, provider, model, version, deployment environment, and cryptographic identity. The agent is the "device" of the agentic world.

### 3. Device reputation → Agent reputation

A device with a history of fraud is risky; so is an agent with a history of blocked or anomalous actions. Reputation accumulates from decision history across sessions and, eventually, across principals.

### 4. IP reputation → Agent infrastructure reputation

Fraud systems score IPs and networks. KATA scores the infrastructure the agent runs on: hosting provider, ASN, network path, TLS posture, and whether the environment changed unexpectedly mid-session. Note the shift below: raw IP reputation *weakens* for agents — what matters is signed, credentialed infrastructure identity.

### 5. Behavioral biometrics → Agent behavioral profile

Keystroke dynamics and mouse movements become tool-usage patterns, API call sequences, retry behavior, and action velocity. The question is the same: *does this behave like the legitimate actor?* The observables change: tool sequences, retry cadence, cart mutation velocity.

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

Merchant risk is also the price. A counterparty with the right domain and the right settlement address can still charge above its own list, add a fee that was never disclosed, or collect twice after reporting a failure. Identity-keyed checks stay quiet, correctly, because the identity is not what is wrong. [AgentCommerceBench](https://github.com/BuildWithGordonAI/agentcommercebench) (Apache-2.0) isolates that shape as its F-family. The class mapping and the draft price and counterparty fields are in [docs/threat-model.md](../docs/threat-model.md) and [docs/intent-model.md](../docs/intent-model.md).

## How agentic AI shifts each signal

Every variable above was designed for one actor per session: a human at a device. Agentic commerce adds a second actor — an AI agent transacting as the human's delegate. Some signals go flat, some matter more. (After the reference article, §12.)

### Signals that weaken

| Variable | Why it weakens | What replaces it |
|---|---|---|
| **IP address** | The agent runs in its provider's cloud — geolocation and ASN describe a datacenter, not a customer. A shopping agent on a cloud ASN is the expected pattern. | Signed request identity verified at the edge; credentialed agent identity. |
| **Device intelligence** | There is no human hand on a phone; the "device" is an ephemeral container. Root/jailbreak checks go dark. | Agent identity and provenance: provider, model, version, attested deployment. |
| **Cookies** | Agents don't browse like returning customers — sessions may be shared across users or discarded each task. | Agent session identifiers bound to delegation, not browser persistence. |

### Signals that strengthen

| Variable | Why it strengthens | KATA implication |
|---|---|---|
| **Phone** | Step-up authentication must reach the *human*, not the agent session. SIM-swap recency stays the highest-value phone signal. | `STEP_UP` / `HUMAN_APPROVAL` ceremonies must route out-of-band to the principal. |
| **Address** | When the shopper is software, where the goods ship is one of the few anchors left — drop-address linkage, first-order-to-new-address, delivery velocity. | Shipping/destination constraints belong in structured intent; monitor them as intent signals. |
| **Identity proofing (SSN / synthetic)** | Agents can assemble synthetic-identity applications programmatically, at machine scale. | Enrollment-time verification and synthetic-identity scoring carry more of the total load — principal verification matters *before* delegation. |
| **Behavioral biometrics → agent-behavior profiling** | Agents don't type or click; classic scores give way to tool sequences, retry cadence, cart mutation velocity. | This is KATA's Behavior layer: profile the agent's *action patterns*, not a human's body. |

### Signals that hold steady

| Variable | Why it holds | KATA implication |
|---|---|---|
| **Email** | Enrollment, verification, and step-up messages still must reach the human behind the agent; an inbox changed ahead of disbursement stays an account-takeover tell. Sender authentication (DMARC/SPF) gains weight as agents send mail for owners. | Principal contact-channel integrity is part of delegation trust. |
| **Payment instrument** | BIN profile, prepaid flags, and issuing-country mismatches are card-level, not device-level. The wallet network token the agent transacts with becomes the trust anchor: issuance recency, spend caps, merchant allowlists. | Transaction-risk component unchanged; token metadata becomes first-class intent constraints. |
| **Bank account** | Ownership validation and return history change little by channel. Agent-initiated payouts raise the stakes on payee and payout-destination changes — step up the *change itself*, not just the transaction. | Destination-change actions should trigger re-evaluation even when the amount looks normal. |

**The net effect: assessment shifts from device trust to delegation trust.** Risk decisions split into two verdicts: *is this agent legitimate, and does this action match the grant?* — which is exactly KATA's WHO/authorized-by-WHOM vs. WHAT/intended/BEHAVING split. Production settlements point the same way: AgentCommerceBench keys history on `agent_id` because that field is populated on 100% of settlements and `session_id` on 0.47%. A session is a weak join key. The agent, and the delegation behind it, is the one that is actually there.

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

Fraud teams win by **correlating, not by collecting**: a new device, a fresh VoIP number, an inconsistent identity, and a first transaction to a drop address are each merely suspicious; together, they are a conclusion.

**The linkage principle.** Every event should join to history on each identifier: how many accounts has this phone touched? This device? This agent? This delegation? The counts, plus their recency, are the cheapest and most decisive features in most fraud models — and the simplest forensic story to tell a reviewer, a regulator, or a jury. KATA should track linkage counts and recency across principals, agents, delegations, and counterparties as first-class context.

**Cost discipline.** Cheap signals (geolocation, line type, delegation-validity checks) run on every event; passively collected signals (behavioral profiles, reputation) layer on continuously; the expensive, high-friction ones (identity verification, SIM-swap queries, deep reputation lookups) fire only at step-up moments. KATA's architecture should follow the cost curve — see [docs/architecture.md](docs/architecture.md).

## Illustrative provider landscape

Representative solution providers by variable (from the reference article; names are illustrative examples from the market, **not endorsements** — capabilities and ownership change, so verify current offerings):

| Variable | Representative providers | Decision role |
|---|---|---|
| IP address | IPQualityScore, MaxMind, Fingerprint, LexisNexis ThreatMetrix | Geo, anonymity, reputation, velocity gating on every event |
| Phone | Telesign, Prove, Ekata (Mastercard), Socure, iconectiv | Type/tenure always; SIM-swap and risk scoring at step-up |
| Email | AtData (Experian), LexisNexis Emailage, SEON | Tenure, domain class, deliverability; linkage at onboarding |
| Device intelligence | LexisNexis ThreatMetrix, Fingerprint, SHIELD, TransUnion iovation | Device risk verdicts and cross-industry reputation |
| Behavioral biometrics | BioCatch (Visa), NuData (Mastercard), BehavioSec (LexisNexis) | Continuous in-session risk, ATO and scam detection |
| Payment instrument | Visa (VAAI), Ethoca/Verifi, Riskified, Forter, Signifyd | BIN profile, prepaid flags, 3DS outcomes, wallet-token context |
| Bank account | GIACT (LSEG), Early Warning, Plaid (Signal), Finicity (Mastercard) | Ownership validation, account age, return history |
| Orchestration | Alloy, FICO, Feedzai, Featurespace (Visa) | Routes events to vendors; approve / step-up / review / decline |

KATA's role relative to these providers: **consumer and correlator**, not competitor. These vendors produce signals and verdicts on individual variables; KATA's risk graph correlates them with delegation, intent, and agent behavior into one explainable decision.

## Using this mapping

- **For fraud practitioners:** this is the on-ramp. Your existing signal taxonomy maps almost 1:1 — the mental models transfer, and the "shifts" section tells you which instincts to retrain.
- **For agent builders:** these are the signals your agents will be judged on. Design for observability: structured intents, attributable actions, stable identities — and remember that cloud-ASN traffic is expected, while unattributable actions are not.
- **For the framework:** each pair is a work item — defining exactly how the agentic equivalent is measured, exchanged, and standardized.

## Privacy and fairness

Collecting and using these signals comes with responsibility: be clear about what is collected and why, follow GDPR/CCPA and sector rules, keep data only as long as needed, and test models for unfair impact on protected groups. **Every adverse decision should be explainable.** Good fraud programs protect customers twice: from criminals, and from being wrongly treated as one. KATA's explainability requirement ([docs/risk-model.md](docs/risk-model.md)) exists for exactly this reason.
