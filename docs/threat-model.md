# KATA Threat Model

**Status: Concept / Open Design — not production ready.**

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

## Threats

| Threat | Description | KATA layer(s) that detect / mitigate |
|---|---|---|
| **Prompt injection → intent drift** | Malicious content in the agent's context steers actions away from the principal's original intent. | Intent module (drift detection), Behavior module (anomaly on tool/API sequences), continuous re-evaluation |
| **Delegation token theft / replay** | Stolen or replayed delegation credentials authorize actions the principal never granted. | Delegation verification (freshness, nonce, expiry, revocation checks) |
| **Scope creep** | The agent incrementally widens what it does — slightly over budget, slightly broader merchants, slightly more data access — staying under any single tripwire. | Intent module (cumulative distance from intent), decision escalation on trend |
| **Agent impersonation** | A rogue agent presents another agent's identity to inherit its reputation and delegations. | Identity module (cryptographic identity, provenance verification) |
| **Infrastructure hijack** | The agent's runtime, tools, or network path are compromised, changing what "the agent" actually does. | Identity module (deployment environment, infra reputation), Behavior module (unexpected infra changes) |
| **Data exfiltration via tool chaining** | A sequence of individually benign tool calls assembles into an exfiltration path (read → transform → send). | Behavior module (tool chaining anomalies), Action evaluation before execution |
| **Intent tampering** | The structured intent record is modified to permit what the principal never allowed. | Intent integrity (signing, audit trail), delegation-intent consistency checks |
| **Revocation failure** | A revoked delegation remains usable because revocation didn't propagate. | Delegation lifecycle (revocation propagation, short-lived delegations, freshness checks) |
| **Approval fatigue / coercion** | A human principal rubber-stamps `HUMAN_APPROVAL` requests, or is pressured into approving. | Policy (approval thresholds, step-up before human approval, rate limits on approvals) |

## Mitigations by KATA principle

- **Authenticate ≠ trust.** Every mitigation starts from: valid identity and valid delegation are necessary but never sufficient.
- **Intent as a guardrail.** Structured, signed intent makes scope creep and drift measurable instead of vibes.
- **Behavior as evidence.** Continuous behavioral profiling catches compromised and misbehaving agents even when credentials are valid.
- **Decisions with teeth.** `QUARANTINE` and `REVOKE` exist so detection leads to containment, not just logging.
- **Explainability.** Every decision carries reasons, so mitigations can be audited and tuned.

## Out of scope

- Vulnerabilities in the underlying model (training data poisoning, weight theft) — handled by model security, consumed as identity/security-posture evidence by KATA.
- Endpoint security of the principal's devices.
- Legal liability assignment when an authorized agent causes harm — listed as an open question in [KATA.md](../KATA.md#25-open-questions).
- Specific cryptographic protocol design (left to future work and existing standards).
