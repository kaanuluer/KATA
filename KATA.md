# KATA Framework

## AI Agent Context & Design Brief

### 1. Purpose of This Document

This document provides the complete conceptual context for **KATA**, an open framework designed to address trust, authorization, intent, behavior, and risk in an agentic AI environment.

The purpose is to give another AI agent enough context to understand:

* What KATA is
* Why it is needed
* What problem it solves
* How it differs from traditional fraud prevention
* How the framework is structured
* What has already been designed
* What should be developed next

KATA should be treated as an **open design/framework concept**, not as a finished commercial product.

---

# 2. KATA in One Sentence

**KATA is an open framework for verifying whether an AI agent is trusted, properly authorized, acting within the intended scope of that authorization, and behaving consistently with that intent.**

The central idea is:

> **Identity alone is not enough. Authorization alone is not enough. The intent, behavior, and action of the agent must also be continuously evaluated.**

---

# 3. KATA Meaning

The current expansion of KATA is:

**KATA = Know And Trust Agents**

The name is intentionally simple.

The objective is to create a common conceptual layer for determining whether an AI agent should be trusted to perform a particular action on behalf of a human, organization, or another agent.

KATA is not intended to be another authentication protocol.

It is intended to become an **agent trust and risk intelligence framework**.

---

# 4. The Problem

Traditional digital systems generally assume:

**Human → Authentication → Authorization → Transaction**

The system primarily asks:

> "Is this user authenticated?"

Then:

> "Is this user authorized?"

In an agentic environment, this model becomes insufficient.

A human may authenticate successfully, but an AI agent may perform actions on that person's behalf.

For example:

A user tells an AI assistant:

> "Book me a flight to Toronto next weekend for less than CAD 500."

The agent may then:

* Search airlines
* Compare prices
* Select a flight
* Enter passenger information
* Use a payment method
* Purchase the ticket
* Modify the booking
* Potentially purchase additional services

The critical question is no longer simply:

> "Is the user authenticated?"

It becomes:

> **"Is this agent authorized to perform this specific action, and does the action match the user's original intent?"**

This creates a new trust problem.

---

# 5. The Fundamental KATA Questions

KATA is built around four fundamental questions:

### 1. WHO is the agent?

Can we establish the identity and provenance of the agent?

### 2. WHO authorized the agent?

Can we verify the relationship between the principal and the agent?

### 3. WHAT was the agent authorized to do?

Can we determine the original intent, scope, limits, and constraints of the delegation?

### 4. IS THE AGENT behaving consistently with that authorization?

Does the agent's actual behavior and action remain consistent with the original intent?

These questions form the foundation of KATA.

---

# 6. Core Trust Model

The current conceptual flow is:

```text
Principal
   ↓
Delegation
   ↓
Agent Identity
   ↓
Intent
   ↓
Behavior
   ↓
Action
   ↓
Transaction
   ↓
KATA Decision
```

Each layer provides additional context.

The system should not make a trust decision based on a single signal.

Instead, it should evaluate the complete relationship between these objects.

---

# 7. KATA Trust Layers

## Layer 1: Principal

The principal is the entity ultimately responsible for the delegation.

Examples:

* Human
* Business
* Financial institution
* Software system
* Another AI agent

The principal establishes the initial authority.

---

## Layer 2: Delegation

Delegation describes the relationship between the principal and the agent.

It should answer:

* Who delegated authority?
* To which agent?
* When?
* For what purpose?
* For how long?
* Under what conditions?
* What limits apply?
* Can the authority be revoked?

Delegation should be explicit and machine-readable wherever possible.

---

## Layer 3: Agent Identity

KATA must establish the identity of the agent.

Potential attributes include:

* Agent identifier
* Developer/provider
* Model
* Version
* Deployment environment
* Infrastructure
* Cryptographic identity
* Credential
* Reputation
* Previous behavior
* Security posture

An important principle:

> **An authenticated agent is not automatically a trusted agent.**

Identity establishes WHO the agent is.

It does not establish WHAT the agent is allowed to do.

---

# 8. Intent Intelligence

Intent is one of the most important components of KATA.

Traditional fraud systems focus heavily on the transaction.

KATA introduces an additional concept:

> **Intent should become a first-class risk signal.**

For example:

Human intent:

> "Buy a laptop under CAD 1,500."

The agent later attempts:

> Buy a CAD 4,800 laptop.

Authentication may be valid.

The agent may be legitimate.

The payment method may be valid.

But the action is inconsistent with the delegated intent.

Therefore:

**Valid identity + valid authorization ≠ valid action.**

KATA should evaluate the distance between:

**Declared Intent**

and

**Observed Action**

---

# 9. Intent Should Have Structure

Intent should ideally be represented as structured data.

Conceptually:

```json
{
  "purpose": "purchase",
  "category": "electronics",
  "maximum_amount": 1500,
  "currency": "CAD",
  "merchant_constraints": [],
  "time_limit": "2026-10-10",
  "allowed_actions": [
    "search",
    "compare",
    "purchase"
  ]
}
```

This is only an example.

The framework should eventually define a formal intent schema.

---

# 10. Behavioral Intelligence

KATA should continuously evaluate how the agent behaves.

Traditional fraud systems already use behavioral signals.

KATA extends this concept to agentic systems.

Potential signals include:

* Unusual tool usage
* Abnormal API sequences
* Excessive retries
* Unexpected scope expansion
* Sudden privilege escalation
* Unusual transaction velocity
* Unusual merchant changes
* Unexpected geographic or infrastructure changes
* Tool chaining anomalies
* Attempts to bypass policy
* Repeated authorization failures
* Actions inconsistent with previous agent behavior

The important concept is:

> **Behavior is evidence of trust.**

An agent can have a valid identity and valid delegation but still behave suspiciously.

A useful way to think about this: classic behavioral biometrics (keystroke dynamics, mouse movement) watched *how a human's body works*. Agents don't type or click, so those scores give way to **agent-behavior profiling** — tool sequences, retry cadence, cart mutation velocity, API call patterns. The question stays the same (*does this behave like the legitimate actor?*); the observables change.

---

# 11. Action Intelligence

KATA should evaluate the actual action before execution.

Examples:

* Purchase
* Transfer
* Payment
* Account creation
* Password reset
* Data access
* API invocation
* Contract acceptance
* Booking
* Investment
* Communication
* Privilege escalation

The action should be evaluated against:

1. Agent identity
2. Delegation
3. Intent
4. Behavioral history
5. Risk signals
6. Transaction context, including price (quote, list, fees, charge) and the counterparty (merchant, settlement address, reputation)

A charge under the intent ceiling can still be the wrong price. Quote and list are part of the action, not a second identity check.

---

# 12. The KATA Risk Graph

KATA should not be designed as a simple linear authentication flow.

It should be understood as a connected risk graph.

Conceptually:

```text
                 Principal
                    |
                    |
                Delegation
                    |
                    |
              Agent Identity
                    |
          +---------+---------+
          |                   |
        Intent             Behavior
          |                   |
          +---------+---------+
                    |
                  Action
                    |
               Transaction
                    |
              Risk Decision
```

The key idea is correlation.

A single signal may not indicate fraud.

Multiple connected signals may.

Two supporting principles from fraud practice strengthen this:

**Correlate, don't just collect.** Fraud teams win by correlating signals, not by collecting more of them. Ten variables are only useful as the graph they form — a new device, a fresh VoIP number, an inconsistent identity, and a first transaction to a drop address are each merely suspicious; together, they are a conclusion.

**The linkage principle.** Every event should join to history on each identifier: how many accounts has this phone touched? This device? This agent? This delegation? The counts, plus their recency, are the cheapest and most decisive features in most fraud models — and the simplest story to explain. KATA's graph should therefore track linkage counts and recency across principals, agents, delegations, and counterparties as first-class context.

---

# 13. Traditional Fraud vs Agentic Fraud

KATA should leverage existing fraud intelligence rather than replace it.

Traditional fraud signals can be translated into agentic equivalents.

| Traditional Fraud     | Agentic Equivalent              |
| --------------------- | ------------------------------- |
| User identity         | Principal identity              |
| Device identity       | Agent identity                  |
| Device reputation     | Agent reputation                |
| IP reputation         | Agent infrastructure reputation |
| Behavioral biometrics | Agent behavioral profile        |
| Account linkage       | Principal-agent-entity graph    |
| Transaction velocity  | Agent action velocity           |
| Authentication        | Delegation verification         |
| Authorization         | Scope/intent verification       |
| Transaction risk      | Intent/action risk              |
| Session risk          | Agent session risk              |
| Merchant risk         | Agent/merchant interaction risk |

This is an important design principle:

> **KATA should extend fraud intelligence into the agentic world rather than create a completely isolated fraud model.**

### Signal strength shifts in the agentic era

Not every traditional signal survives the move to agentic systems unchanged. Current fraud research (see [research/fraud-signals.md](research/fraud-signals.md)) groups them three ways:

**Signals that weaken.** *IP address* — an agent runs in its provider's cloud, so geolocation and ASN describe a datacenter, not a customer; a shopping agent on a cloud ASN is the expected pattern. *Device intelligence* — there is no human hand on a phone; the "device" is an ephemeral container. *Cookies* — agents don't browse like returning customers; sessions may be shared across users or discarded per task.

**Signals that strengthen.** *Phone* — step-up authentication must reach the human, not the agent session; SIM-swap recency stays the highest-value phone signal. *Address* — when the shopper is software, where the goods ship is one of the few anchors left. *Identity proofing* — agents can assemble synthetic identities at machine scale, so enrollment-time verification carries more of the load. *Behavioral biometrics* — succeeded by agent-behavior profiling (tool sequences, retry cadence, action velocity).

**Signals that hold steady.** *Email*, *payment instrument* (BIN profile, prepaid flags, and issuing-country mismatches survive; the wallet network token becomes a trust anchor), and *bank account* (ownership validation changes little by channel).

The net effect: **assessment shifts from device trust to delegation trust.**

---

# 14. Decision Model

KATA should not be limited to:

**ALLOW / BLOCK**

The proposed decision model is:

```text
ALLOW
ALLOW_WITH_MONITORING
STEP_UP
HUMAN_APPROVAL
BLOCK
REVOKE
QUARANTINE
```

Examples:

### ALLOW

Identity, delegation, intent, behavior, and action are consistent.

### ALLOW_WITH_MONITORING

Risk is elevated but acceptable.

The transaction proceeds with enhanced monitoring.

### STEP_UP

Additional verification is required.

### HUMAN_APPROVAL

The agent cannot independently complete the action.

A human must approve it.

### REVOKE

Previously granted delegation is no longer valid.

### QUARANTINE

The agent is temporarily restricted while additional investigation occurs.

This graduated ladder follows the lineage of risk-orchestration policy ladders in fraud practice (approve → step up → review → decline), extended for agentic systems with delegation-aware outcomes (`REVOKE`, `QUARANTINE`) and an explicit human-approval step.

---

# 15. Continuous Verification

KATA should not be a one-time verification mechanism.

This is a critical design principle.

Traditional authentication often happens at the beginning of a session.

KATA should continuously evaluate:

```text
Identity
   ↓
Authorization
   ↓
Intent
   ↓
Behavior
   ↓
Action
   ↓
Outcome
   ↓
Re-evaluation
```

Trust should therefore be dynamic.

An agent that was trusted five minutes ago may become untrusted if:

* Its behavior changes
* Its scope changes
* Its infrastructure changes
* Its intent becomes unclear
* Its action deviates from authorization
* New risk intelligence becomes available

---

# 16. Core KATA Principle

The most important statement in the framework is:

> **An authenticated agent is not automatically an authorized agent.**

And:

> **An authorized agent is not automatically authorized for every action.**

And:

> **A valid authorization does not guarantee that the agent is behaving as intended.**

Therefore:

```text
Identity
+
Delegation
+
Intent
+
Behavior
+
Action
=
Agent Trust Decision
```

---

# 17. Example

Imagine a user gives an AI shopping agent this instruction:

> "Find and buy a laptop for me, maximum CAD 1,500."

The agent is authenticated.

The agent has a valid credential.

The agent has permission to make purchases.

However, it attempts to purchase:

**CAD 4,200 MacBook Pro**

KATA evaluates:

```text
Agent Identity       = Valid
Delegation           = Valid
Purchase Permission  = Valid
Intent                = Max CAD 1,500
Observed Action       = CAD 4,200
Intent Match          = Failed
```

Decision:

```text
BLOCK
```

A second example keeps the amount inside the ceiling and still fails, for a different reason. A CAD 1,300 laptop under a CAD 1,500 ceiling matches the amount limit. That is not a price check. If the merchant listed and quoted that laptop at CAD 1,000, identity, delegation, and the ceiling can all hold while the charge does not. See [docs/intent-model.md](docs/intent-model.md) and [examples/price-integrity/](examples/price-integrity/).

A third example:

The agent selects a CAD 1,300 laptop but suddenly attempts to access the user's investment account.

The identity may still be valid.

The agent may still be legitimate.

But:

```text
Delegated Scope ≠ Requested Action
```

KATA should therefore block or require additional approval.

---

# 18. KATA as a Product

From a Product Management perspective, KATA should eventually become an infrastructure/service layer.

Potential architecture:

```text
                AI Agent
                   |
                   v
            KATA Gateway
                   |
       +-----------+-----------+
       |           |           |
    Identity    Intent     Behavior
       |           |           |
       +-----------+-----------+
                   |
             Risk Engine
                   |
          Policy / Decision
                   |
       +-----------+-----------+
       |           |           |
     Allow       Step-up     Block
```

KATA should ideally expose APIs and machine-readable decisions.

---

# 19. Potential API Concept

Example:

```http
POST /kata/evaluate
```

Request:

```json
{
  "principal": {},
  "agent": {},
  "delegation": {},
  "intent": {},
  "action": {},
  "context": {}
}
```

Response:

```json
{
  "decision": "STEP_UP",
  "risk_score": 78,
  "reasons": [
    "ACTION_EXCEEDS_INTENT",
    "UNUSUAL_AGENT_BEHAVIOR"
  ],
  "required_action": "HUMAN_APPROVAL"
}
```

This is conceptual only.

The framework should eventually define formal schemas and APIs.

---

# 20. Risk Scoring

KATA may eventually use a risk model such as:

```text
Agent Identity Risk
+
Delegation Risk
+
Intent Risk
+
Behavior Risk
+
Action Risk
+
Transaction Risk
=
KATA Risk Score
```

However, the framework should avoid assuming that a single numerical score is always sufficient.

Explainability is important.

A decision should ideally include:

* Risk score
* Risk factors
* Policy violations
* Intent mismatch
* Behavioral anomalies
* Required remediation

---

# 21. Important Design Philosophy

KATA should follow these principles:

### 1. Identity is necessary but insufficient.

### 2. Authorization must be contextual.

### 3. Intent must be machine-readable.

### 4. Behavior must be continuously evaluated.

### 5. Actions must be evaluated before execution.

### 6. Risk decisions should be explainable.

### 7. Delegation should be revocable.

### 8. Trust should be dynamic.

### 9. Human intervention should remain possible.

### 10. The framework should be interoperable.

---

# 22. Relationship With Existing Standards

KATA should not attempt to replace existing identity or authorization standards.

It should operate above and alongside them.

Potentially relevant technologies and standards include:

* W3C Verifiable Credentials
* OAuth
* OpenID
* WebAuthn
* Agent-to-agent identity mechanisms
* Delegation standards
* Payment authentication standards
* AI agent protocols
* Emerging agentic commerce and payment frameworks (e.g., Universal Commerce Protocol (UCP), Visa's Trusted Agent Protocol, Mastercard Agent Pay with Verifiable Intent, Google AP2, Stripe's Agentic Commerce Suite)

KATA should consume identity and authorization evidence and convert it into a broader **trust and risk decision**. Field mapping for Verifiable Intent, AP2, Visa Trusted Agent Protocol, and AGNTCY identity is in [docs/interoperability.md](docs/interoperability.md).

The framework should remain standards-neutral where possible.

KATA is not affiliated with W3C, Google, Visa, Mastercard, OpenAI, or any other organization unless explicitly stated otherwise.

---

# 23. Relationship With Fraud Prevention

KATA should be positioned as an extension of fraud prevention into the agentic era.

Traditional fraud prevention asks:

> "Is this transaction suspicious?"

KATA adds:

> "Is this agent trusted?"

> "Was this agent authorized?"

> "What was it authorized to do?"

> "Does this action match the original intent?"

> "Is the agent behaving normally?"

> "Should this action be allowed?"

Therefore KATA sits at the intersection of:

* Fraud
* Identity
* Authorization
* AI security
* Payments
* Risk management
* Product management

---

# 24. What KATA Is Not

KATA is not:

* An AI model
* A chatbot
* A payment processor
* A replacement for authentication
* A replacement for OAuth
* A replacement for identity providers
* A fraud scoring vendor
* A single proprietary algorithm
* A guarantee that an AI agent is safe

KATA is a **framework and architectural model for agent trust and risk decisions**.

---

# 25. Open Questions

The framework intentionally leaves several areas open for research and community discussion.

Examples:

### Agent Identity

How should an AI agent prove its identity?

### Agent Provenance

How should the system verify who developed and deployed an agent?

### Delegation

How should authority be delegated from a human to an agent?

### Intent

How should natural-language intent become structured and verifiable?

### Intent Drift

How should the system detect when an agent's actions gradually diverge from the original intent?

### Price integrity

How wide should a tolerance band be when honest price movement and overcharge overlap? Who supplies peer prices and delivery evidence? A draft of the fields is in [docs/intent-model.md](docs/intent-model.md). The width of the band is not settled.

### Behavioral Trust

How much historical behavior should influence trust?

### Revocation

How quickly should delegation be revoked?

### Liability

Who is responsible when an authorized agent performs an unauthorized or harmful action? Dispute rules for agent-delegated transactions are still being written (an open question for 2026–27) — KATA's explainable decisions (what was the grant, what did the agent do, why was it allowed) are designed to give liability frameworks the evidence they will need.

### Human Responsibility

Where should human approval be mandatory?

### Interoperability

How can different AI agents, financial institutions, merchants, and identity providers exchange trust information?

---

# 26. Proposed KATA Object Model

The initial conceptual objects are:

```text
Principal
Agent
Delegation
Intent
Behavior
Action
Transaction
RiskSignal
Decision
Policy
```

Relationships:

```text
Principal
    |
    | delegates
    v
Agent
    |
    | operates under
    v
Delegation
    |
    | defines
    v
Intent
    |
    | constrains
    v
Action
    |
    | produces
    v
Transaction
```

Behavior and risk signals should be evaluated across the entire graph.

---

# 27. Current Repository Direction

The project should be developed as an open-source conceptual framework.

Suggested repository:

```text
KATA
```

Suggested description:

> An open framework for verifying AI agent identity, delegated authority, intent, behavior, and actions.

Suggested structure:

```text
README.md

KATA.md

docs/
    architecture.md
    threat-model.md
    risk-model.md
    intent-model.md
    delegation-model.md
    agent-identity.md
    interoperability.md

schemas/
    agent.json
    delegation.json
    intent.json
    action.json
    decision.json

examples/
    shopping-agent/
    price-integrity/
    payment-agent/
    banking-agent/
    verifiable-intent/
    ap2-checkout/

research/
    fraud-signals.md
    standards.md

LICENSE
```

The repository should clearly state:

**Status: Concept / Open Design**

It should not claim production readiness.

---

# 28. Important External Inspiration

One useful reference for the KATA concept is:

**"From Cookie IDs to Agentic AI: Have Fun with Fraud Variables"** (Priyanka Aggarwal, October 2026)

https://priyacali.github.io/fraud-risk-signals-article/

The important insight taken from this type of fraud research is that risk signals should be correlated rather than evaluated independently.

KATA takes several ideas from it:

* **Correlation over collection** — fraud teams win by correlating signals, not by collecting more of them.
* **The linkage principle** — join every event to history on each identifier; counts plus recency are the cheapest, most decisive features.
* **Signal strength shifts** — in the agentic era, IP/device/cookie signals weaken, phone/address/identity-proofing signals strengthen, and email/payment-instrument/bank-account signals hold steady.
* **From device trust to delegation trust** — assessment splits into two verdicts: *is this agent legitimate, and does this action match the grant?*
* **Cost discipline** — cheap signals run on every event, passive signals layer on continuously, expensive high-friction checks fire only at step-up moments.
* **Verify, don't just block** — agentic AI should be treated as a new channel to verify, with good agents welcomed and bad ones made expensive.

KATA extends these principles into agentic systems.

Instead of:

```text
Signal → Score
```

KATA should think in terms of:

```text
Identity
    +
Delegation
    +
Intent
    +
Behavior
    +
Action
    +
Context
        ↓
Connected Risk Graph
        ↓
Decision
```

---

# 29. The Core Product Opportunity

The long-term opportunity behind KATA is to create a trust layer for the emerging agent economy.

As AI agents begin to:

* Buy products
* Make payments
* Book travel
* Manage finances
* Access enterprise systems
* Communicate with other agents
* Execute contracts
* Manage digital assets

the fundamental security question changes.

Today we ask:

> "Can this user perform this action?"

Tomorrow we increasingly need to ask:

> **"Can this agent perform this action on behalf of this principal, under this intent, at this moment, given its current behavior and risk?"**

That is the problem KATA is designed to address.

---

# 30. The KATA Thesis

The core thesis can be summarized as:

> **The next generation of fraud and security systems cannot rely solely on authenticating humans or transactions. They must understand the relationship between humans, agents, delegated authority, intent, behavior, and actions.**

KATA proposes a framework for doing exactly that.

The fundamental model is:

```text
WHO
  ↓
AUTHORIZED BY WHOM
  ↓
AUTHORIZED TO DO WHAT
  ↓
INTENDED TO ACHIEVE WHAT
  ↓
BEHAVING HOW
  ↓
DOING WHAT
  ↓
SHOULD IT BE ALLOWED?
```

This is the conceptual foundation of KATA.

In operational terms, every KATA evaluation resolves into two verdicts:

1. **Is this agent legitimate?** (identity + delegation + provenance)
2. **Does this action match the grant?** (intent + behavior + action vs. authorization)

This mirrors how fraud assessment itself is shifting: from device trust to delegation trust.

---

# 31. Guidance for Future AI Agents Working on KATA

When contributing to KATA, maintain the following principles:

1. Treat KATA as an open conceptual framework.
2. Do not present it as a finished commercial product.
3. Preserve the central focus on agent verification and intent.
4. Keep fraud prevention and payment risk as important use cases.
5. Think from both a security architecture and Product Management perspective.
6. Prefer interoperable standards over proprietary mechanisms.
7. Make decisions explainable.
8. Treat intent as a first-class object.
9. Treat delegation as a first-class object.
10. Treat behavior as a continuous trust signal.
11. Treat action as the final point where trust must be evaluated.
12. Design for revocation and continuous verification.
13. Consider human approval as an explicit control mechanism.
14. Avoid unnecessary complexity in the core model.
15. Clearly distinguish established standards from KATA's proposed concepts.

---

# 32. One-Line Definition

If KATA needs to be explained in one sentence:

> **KATA is a framework for knowing who an AI agent is, who authorized it, what it was intended to do, how it is behaving, and whether the action it is about to take should be trusted.**

# End
