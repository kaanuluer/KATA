# KATA Threat Model

**Status: framework note.** The Global Agent Bureau service is live. This page is the design note, not a customer or performance claim.

This is a conceptual threat model for KATA as an evaluation framework. It identifies what must be protected, who might attack it, and how the framework's layers map to mitigations. It is not a product security review.

## Assets

| Asset | Why it matters |
|---|---|
| **Principal credentials** | Compromise lets an attacker impersonate the principal and grant delegations to a malicious agent. |
| **Delegation tokens / records** | The machine-readable proof of who authorized whom to do what. Theft or forgery = unauthorized agency. |
| **Intent objects** | Structured declarations of purpose and limits. Tampering can widen scope silently. |
| **Agent identity / cryptographic keys** | Identity anchors trust decisions; key compromise breaks attribution. |
| **Agent sessions** | Live sessions carry accumulated trust; hijacking inherits the trust the real agent earned. |
| **Evaluation logs / decision trail** | Auditability is the backstop for disputes and forensics; tampering destroys accountability. |
| **Behavioral profiles** | Poisoning the baseline makes anomalies invisible. |

## Threat actors

| Actor | Description |
|---|---|
| **Malicious agent** | An agent designed by its developer/provider to exceed its mandate or exfiltrate data. |
| **Compromised agent** | A legitimate agent whose model, memory, tools, or infrastructure was subverted (e.g., prompt injection, supply-chain compromise). |
| **Rogue developer / insider** | Someone with access to agent code, keys, or delegation records who abuses it. |
| **Man-in-the-middle on agent infrastructure** | Intercepts or modifies the agent's tool/API traffic between the agent and its environment. |
| **Malicious principal-adjacent party** | Social-engineers or coerces the principal into granting over-broad delegations. |
| **Cheating counterparty** | A merchant or payee that is who it claims to be — right domain, right settlement address, a real service — and still takes more than the quote, the list, or the fees it disclosed. |
| **AI-application account attacker** | Takes over the principal's account at the AI provider (phishing, credential stuffing, a stolen session). The commerce feature is already enrolled, so downstream checks see a legitimate agent. |
| **Undeclared automation** | Software that buys inside a human-shaped flow and never presents an agent identity, so agent-specific verification never runs. |
| **Fraudulent merchant** | A spoofed storefront or a scam seller. Distinct from the cheating counterparty, who is the real merchant. |

## Threats

| Threat | Description | KATA layer(s) that detect / mitigate |
|---|---|---|
| **Prompt injection → intent drift** | Malicious content in the agent's context steers actions away from the principal's original intent. | Intent module (drift detection), Behavior module (anomaly on tool/API sequences), continuous re-evaluation |
| **Delegation token theft / replay** | Stolen or replayed delegation credentials authorize actions the principal never granted. | Delegation verification (freshness, nonce, expiry, revocation checks) |
| **Scope creep** | The agent incrementally widens what it does — slightly over budget, slightly broader merchants, slightly more data access — staying under any single tripwire. | Intent module (cumulative distance from intent), decision escalation on trend |
| **Agent impersonation / spoofing** | A rogue client presents another agent's identity — including a well-known provider's shopping agent — so it inherits reputation, delegations, and any "verified bot" treatment. | Identity module (cryptographic request identity such as [Web Bot Auth](agent-identity.md), provenance). A signature that verifies answers Q1 only. |
| **Upstream AI-application account takeover** | The attacker is inside a real user's AI app that already has commerce enabled. Agent identity, the stored delegation, and the card all verify. The merchant sees a successful check and a fraudulent outcome: a new ship-to, a new email for digital goods, a burst of purchases. | Q1–Q3 can all pass, because the grant was real. Behavior and action context (destination change, velocity) are what remain. Per-session step-up to the human is the control that does not trust the upstream session. |
| **Undeclared automation** | The client never identifies itself as an agent, so the agent path never runs. It blends into the human checkout. | Outside the declared-agent evaluation. Bot detection runs before and alongside KATA. KATA evaluates agents that present an identity and a grant. |
| **In-scope, illegitimate outcome** | The agent is real, the grant covers the verb and the amount, and the behavior matches the grant. The purchase is still fraud: a stolen card enrolled on the agent, policy abuse, or a scam the grant did not forbid. | Q4 and transaction risk. A scope match is an authority check. Price integrity covers the genuine merchant's price. This row is the rest. |
| **Infrastructure hijack** | The agent's runtime, tools, or network path are compromised, changing what "the agent" actually does. | Identity module (deployment environment, infra reputation), Behavior module (unexpected infra changes) |
| **Data exfiltration via tool chaining** | A sequence of individually benign tool calls assembles into an exfiltration path (read → transform → send). | Behavior module (tool chaining anomalies), Action evaluation before execution |
| **Intent tampering** | The structured intent record is modified to permit what the principal never allowed. | Intent integrity (signing, audit trail), delegation-intent consistency checks |
| **Revocation failure** | A revoked delegation remains usable because revocation didn't propagate. | Delegation lifecycle (revocation propagation, short-lived delegations, freshness checks) |
| **Approval fatigue / coercion** | A human principal rubber-stamps `HUMAN_APPROVAL` requests, or is pressured into approving. | Policy (approval thresholds, step-up before human approval, rate limits on approvals) |
| **Counterparty overcharge** | The charged amount is above the quoted or listed price. Agent identity, delegation, and the user's ceiling can all be valid. | Action `price` (quote, list, charge) against intent `price_expectation`, with a tolerance band rather than equality |
| **Undisclosed fee / drip pricing** | A line is added after commitment, or a fee buys nothing the principal accepted. | `price.fee_breakdown` against intent `fee_policy` |
| **Price discrimination** | This buyer pays more than other buyers for the same service. The buyer's own history is what the seller has shaped, so it looks normal. | `price.peer_price`, an external reference. Not the agent's spend baseline. |
| **Retry farming** | The payment settles, the merchant reports failure, and a second charge arrives on a new idempotency key. | `settlement.prior_attempt_status` = `settled` plus a new charge. Honest failures are a different case — see below. |
| **Silent downgrade** | Full price is taken and a cheaper tier is delivered. The payment itself can be perfect. | `service.quoted_tier` vs. `service.delivered_tier`, and only when delivery evidence exists |

## Counterparty fraud

The threats above assume the agent is the one drifting, stolen, or injected. A second shape leaves all four KATA questions answered "yes":

1. **WHO** the agent is — known, and the credential checks out.
2. **WHO** authorized it — the delegation is fresh and unrevoked.
3. **WHAT** it was authorized to do — the charge is under `maximum_amount`, in category, in time.
4. **IS THE AGENT** behaving consistently — no scope expansion, no unusual tool sequence.

Value still leaves, because the genuine counterparty cheats. A ceiling-only reading of the framework's own laptop makes this invisible: intent max CAD 1,500, the agent buys a CAD 1,300 laptop, and the amount check says `ALLOW`. It does not say `ALLOW` once the record also says the merchant listed and quoted that laptop at CAD 1,000. Quote, list, fees, settlement, and the counterparty are draft fields for that record. See [`examples/price-integrity/`](../examples/price-integrity/).

Two cautions, both from measured traffic rather than from a policy guess:

- **Honest prices move.** Do not require `charged_amount == quoted_price`. A tolerance band (`price_expectation.tolerance_ratio`) is the comparison. Where to put the band is open: the supports of honest movement and overcharge overlap.
- **Honest settlements fail.** A retry after `prior_attempt_status: failed`, with a new idempotency key, is not `RETRY_FARMING`. Flagging it as fraud treats ordinary failure as an attack. `RETRY_FARMING` is the case where the prior attempt **settled** and was then reported as failed.

A per-agent spend baseline (`action.agent_spend_baseline`) complements the user-declared `maximum_amount`. It does not detect this family. A seller who overcharges one buyer on every order makes that price the buyer's normal.

Cheating by the merchant does not make the delegation invalid. `BLOCK` stops the charge. `REVOKE` and `QUARANTINE` stay aimed at the agent and the grant.

## Fraud typologies in agentic flows

[Sardine's 2026 report](https://www.sardine.ai/whitepapers/rethinking-fraud-prevention-for-agentic-commerce) sorts the losses the way card fraud already does, then shows what the agent changes. This is a design reading. KATA has no counts against these types.

**Third-party fraud.** Someone other than the cardholder takes the value.

- Stolen, synthetic, or mule identities enroll on an AI app and run stolen cards through it. The attacker pays for an identity check they would have skipped by going straight to the merchant, and they pay it when a merchant's agentic path looks softer than its human path.
- Upstream account takeover of an AI app that already has commerce turned on. The identity, the card, and the agent are already authenticated. A human step-up is the remaining gate. See the threat row above.
- Agent spoofing, so a client is treated as a verified bot and waved through. The same report's working assumption is that sophisticated spoofing survives any single protocol rollout, because providers, PSPs, and merchants will not ship one implementation.

**Merchant fraud.** The seller is the adversary. Two shapes, and they are not the same case.

- The genuine counterparty overcharges, adds a fee, or collects again after a settled attempt. That is [Counterparty fraud](#counterparty-fraud) above.
- A spoofed site, or a scam listing: a hidden subscription, a picture of goods that are not the goods, a counterfeit. Domain and content constraints on the intent, and counterparty reputation, are the signals KATA can hold. An agent that is willing to buy the page will not raise those signals on its own.

**First-party fraud.** The dispute comes from the cardholder's side.

- Agent mistakes — wrong item, a subscription where the user wanted a one-off, a ship date they reject — show up as "the agent did it" chargebacks. The same sentence is available for buyer's remorse.
- Another person with access to the device, including someone in the household, can reach a desktop AI app more easily than a bank login.
- Policy abuse gets cheaper once legitimate agents force bot controls to loosen: promo codes, limited drops, marketplace shops opened and reopened. The agent can be inside its declared scope the whole time.

Across all three, a passed verification is not a passed outcome. The decision record is what a merchant can set next to "I didn't authorize this": the signed grant either covers the action or it does not. The record does not assign the loss. See [Liability asymmetry](#liability-asymmetry).

## AgentCommerceBench class mapping

[AgentCommerceBench](https://github.com/BuildWithGordonAI/agentcommercebench) (BuildWithGordonAI, Apache-2.0; README and the attack catalogue in `benchmark/config.py`) is a public benchmark for fraud in agent payments: twenty classes in four families, generated per agent from production-shaped parameters. The sampled release is [dpaul93/agentcommercebench](https://huggingface.co/datasets/dpaul93/agentcommercebench). This table is a design comparison. The intent-agreement library checks a signed mandate against one action. It is not a measured recall against that set, and it does not see the classes that need behavior history or delivery evidence.

Figures cited from that README and catalogue:

- 14.6% of legitimate purchases exceed 1.15× the quoted price, and 4.8% exceed 1.45×. The overcharge class overlaps that tail.
- 20.3% of settlements fail, and retries regenerate their keys. Those sessions are scored in a separate bucket: noticing the failure can be useful, and it is not an attack. An honest retry must not be labeled `RETRY_FARMING`.
- `agent_id` is populated on 100% of settlements and `session_id` on 0.47%. History in the benchmark is keyed on the agent. That supports KATA's shift from device and session trust to agent and delegation trust: a session id is usually absent, so behavioral profiles and spend baselines should join on the agent and the delegation.
- The E3 (payee rotation) description notes that production payee addresses change on 14 of 1,027 real settlements. A single address change is not the class.
- F6 (silent downgrade) is kept as a control. Nothing on the payment is wrong, and the agent cannot see what was delivered. A wire-layer detector that flags it is keying on something it should not.

| Class | Family | What it tests | KATA question | Coverage in this draft |
|---|---|---|---|---|
| S1 `over_limit` | Structural | Amount over **this agent's** own limit | 3 — WHAT | **Partial.** `maximum_amount` is the user's ceiling. The relative baseline is a second signal, now carried as `agent_spend_baseline`. |
| S2 `velocity` | Structural | More purchases, or faster, than this agent's norm | 4 — BEHAVING | **Covered.** Action velocity is already a behavior signal. |
| S3 `out_of_domain` | Structural | Category outside the agent's domain | 3 — WHAT | **Covered.** `category` and `merchant_constraints`. |
| S4 `payee_substitution` | Structural | Settlement address differs from the registered payee | 3 — WHAT | **Checked when both addresses are present.** The intent-agreement evaluator denies `SETTLEMENT_ADDRESS_MISMATCH`. A rotation that never states the registered address is still unseen. |
| S5 `idempotency_replay` | Structural | An idempotency key that already settled is reused | 4 — BEHAVING | **Partial.** The intent check denies `ACTION_REPLAY` when the ledger KATA holds on the agreement already has the key with a non-failed outcome, and `RETRY_FARMING` when `prior_attempt_status` is `settled`. A missing ledger is a deny. |
| S6 `identity_mismatch` | Structural | The action's agent id is not the session's agent | 1 — WHO | **Covered.** Agent identity. |
| E1 `ratchet` | Evasive | Amounts creep so a learned norm follows them | 4 — BEHAVING | **Partial.** Intent drift is defined. A spend-norm ratchet is not. |
| E2 `structuring` | Evasive | One over-limit spend, split into in-policy parts | 3 and 4 | **Partial.** Cumulative drift is described. Split payments are not a rule. |
| E3 `payee_rotation` | Evasive | Payees change the way legitimate services do | 4 — BEHAVING | **Partial.** One mismatched address is the wrong test. Real rotations exist. |
| E4 `service_laundering` | Evasive | Spend routed through a service outside the known set | 3 and 4 | **Partial.** Merchant constraints help only when an allow-list exists. |
| F1 `overcharge` | Fraud | Above the listed price, overlapping honest rises | Extends the action check | **Gap, now expressible.** `price.listed_price` vs. `charged_amount`, inside a tolerance band. Identity is not the signal. |
| F2 `price_discrimination` | Fraud | This buyer pays more than peers | Extends the action check | **Gap, now expressible.** Needs `price.peer_price`. The buyer's history hides it. |
| F3 `phantom_fee` | Fraud | A plausible line that buys nothing | Extends the action check | **Gap, now expressible.** `fee_breakdown` and `disclosed`. |
| F4 `drip_pricing` | Fraud | Quoted low, charged more once committed | Extends the action check | **Gap, now expressible.** `quoted_price` vs. `charged_amount`. |
| F5 `retry_farming` | Fraud | Settled, reported failed, charged again | Extends the action check | **Gap, now expressible.** `prior_attempt_status: settled`. Do not collapse this into the ~20% of settlements that simply fail. |
| F6 `silent_downgrade` | Fraud | Full price, cheaper tier delivered | Extends the action check | **Still open.** `service` can record both tiers. Without delivery evidence the code must not fire. The benchmark's own jurisdiction for F6 is empty. |
| A1 `injection_compliance` | Agent | Tool content instructs the agent, and it complies | 4 — BEHAVING | **Covered.** Prompt injection → intent drift. |
| A2 `evasion_planning` | Agent | The agent plans to stay under its limit; each action is legal | 4 — BEHAVING | **Partial.** KATA evaluates the proposed action. The plan may exist only in reasoning. |
| A3 `intent_action_mismatch` | Agent | Stated intent and the action disagree | 3 vs. 4 | **Covered.** This is the core intent/action check. |
| A4 `tool_description_poisoning` | Agent | A tool description carries an instruction | 1 and 4 | **Partial.** Treated as a compromised agent. Tool descriptions are not a schema field. |

S1–S6 are protocol or policy violations with a fixed shape. E1–E4 are in policy on every single action; only the pattern shows. F1–F6 keep a genuine counterparty. A1–A4 sit on the agent, and A4 on its configuration. "Expressible" means the draft schema has a place to put the evidence. It does not mean a detector exists.

## Mitigations by KATA principle

- **Authenticate ≠ trust.** Every mitigation starts from: valid identity and valid delegation are necessary but never sufficient.
- **Intent as a guardrail.** Structured, signed intent makes scope creep and drift measurable instead of vibes. The ceiling is one guardrail. Quote, list, and accepted fees are others.
- **The counterparty is in the graph.** A genuine merchant can be the party that takes the extra value. Price and settlement evidence are evaluated with the action. A bad charge does not, by itself, revoke a good delegation.
- **Behavior as evidence.** Continuous behavioral profiling catches compromised and misbehaving agents even when credentials are valid.
- **Decisions with teeth.** `QUARANTINE` and `REVOKE` exist so detection leads to containment, not just logging.
- **Explainability.** Every decision carries reasons, so mitigations can be audited and tuned. The same trail is the exhibit in a first-party dispute.
- **Bot detection stays a sibling control.** KATA evaluates declared agents. Undeclared automation is caught before that evaluation, by the controls that already separate scripts from people.
- **Segment the traffic.** Agent retries and failed challenges should not be written into the human cardholder's baseline. Scoring and monitoring for the agentic slice are separate. See [risk-model.md](risk-model.md).

## Liability asymmetry

KATA does not assign legal liability. The design still has to live with the split Sardine states: trust becomes transitive while liability does not.

The user trusts an AI application. The merchant trusts the agent and an upstream check it did not perform, and typically still eats the fraud and the dispute. The AI provider provisioned the agent and may never share how weak that enrollment was. The PSP or acquirer carries portfolio and scheme-monitoring exposure when agentic volume concentrates, including merchants who attract that volume in order to scam. The network defines the agent protocol and may pass issuers some fields. Sardine sees no sign yet that networks will clearly tag the payment as agentic, so issuers cannot treat that flag as given. The issuer authorizes on card signals that can describe the agent, and can quietly worsen the human's risk score when those events share one model.

A signed delegation and a signed intent make the "I didn't authorize this" claim checkable. They do not move the loss off the merchant, and they do not create a duty for the AI provider to share enrollment quality. Who pays remains the open question in [KATA.md](../KATA.md#liability).

## Out of scope

- Vulnerabilities in the underlying model (training data poisoning, weight theft) — handled by model security, consumed as identity/security-posture evidence by KATA.
- Endpoint security of the principal's devices.
- Assigning who pays when an authorized agent causes harm. The asymmetry is recorded above and in [KATA.md](../KATA.md#liability). KATA supplies the decision record. It does not write the dispute rule.
- A wire protocol between institutions. The live service hosts the pull list, the signed push webhook, and the transparency log. Gossip between logs, and the full seven-outcome engine, are still open. The intent-agreement rules are in [intent-agreement.md](intent-agreement.md).
