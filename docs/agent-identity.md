# KATA Agent Identity

**Status: Concept / Open Design — not production ready.**

Agent identity answers the first KATA question — **WHO is the agent?** — covering identity attributes, provenance verification, and reputation. It establishes *who the agent is*, which is necessary but never sufficient for trust.

## Identity attributes

| Attribute | Description |
|---|---|
| `agent_id` | Unique, stable identifier for the agent instance. |
| `developer` / `provider` | Who built and who operates the agent (may differ). |
| `model` | The underlying model family/identifier. |
| `model_version` | Version or snapshot — behavior changes between versions. |
| `deployment_environment` | Where the agent runs (cloud region, on-device, enterprise VPC, etc.). |
| `infrastructure` | Network identity: IP ranges, ASN, TLS posture, attestation where available. |
| `cryptographic_identity` | Keys, certificates, or attestations binding the agent to its identity (e.g., SPIFFE/SVID concepts — see [research/standards.md](../research/standards.md)). |
| `credentials` | Tokens or credentials the agent presents; includes issuance, scope, and freshness metadata. |
| `reputation` | Accumulated trust signal from past behavior across principals (see below). |
| `behavior_history` | Summary of prior sessions: volume, anomaly rate, decision history. |
| `security_posture` | Known posture signals: patch level, sandboxing, tool permissions, audit status. |

The normative schema draft is [`schemas/agent.json`](../schemas/agent.json).

## Provenance verification

Identity without provenance is a name tag anyone can wear. KATA needs answers to:

- **Who developed this agent?** Verifiable link between the agent and its developer/provider.
- **Who deployed it, and where?** The deployment environment and infrastructure should be attestable, not self-asserted.
- **Has it changed?** Model version, code, and configuration changes should be detectable — a new version is, for trust purposes, a partially new agent.

Mechanisms are deliberately left to existing standards (verifiable credentials, workload identity like SPIFFE/SPIRE, code signing, Web Bot Auth below). KATA's role is to **consume provenance evidence** and fold it into the identity-risk component — not to invent another identity protocol.

## Web Bot Auth

[IETF Web Bot Auth](https://datatracker.ietf.org/wg/webbotauth/about/) (`webbotauth`) is the working group standardizing cryptographic authentication of automated clients to websites built for people. The in-scope uses include AI agents retrieving or acting on content for an end user. The active drafts sign the HTTP request with HTTP Message Signatures (RFC 9421) and point at a key the operator publishes, so the site checks a signature instead of inferring a bot from the user agent or the IP address. The work is an emerging standard: the working group is active, and the signature protocol is still an Internet-Draft, not an RFC.

Visa's Trusted Agent Protocol and Mastercard Agent Pay use that layer for commerce agents. Sardine's 2026 report *[Rethinking Fraud Prevention for Agentic Commerce](https://www.sardine.ai/whitepapers/rethinking-fraud-prevention-for-agentic-commerce)* makes the same observation: both schemes' agent protocols are built on Web Bot Auth, so a merchant can receive an explicit, tamper-evident signal that the caller is a declared agent of a known provider. Public descriptions of the two protocols say the same thing. See [research/standards.md](../research/standards.md#ietf-web-bot-auth).

For KATA this evidence answers Q1:

- A valid signature says the request was made by an agent that provider stands behind. Agent spoofing — wearing a known agent's name to inherit its treatment — becomes a key-compromise problem rather than a header problem.
- Who the principal is requires a separate binding. A consumer-recognition object that rides along, as in Visa's protocol, is still principal context. It is not a KATA intent.
- What the agent was authorized to buy is Q3, and it is not in the bot signature.
- A client that never declares itself never presents the signature. That traffic is undeclared automation. Bot detection has to see it before KATA is asked. KATA evaluates declared agents. Bot detection and KATA run together: one for clients that hide, one for clients that identify themselves.

KATA stays standards-neutral and consumes the verification result. It does not freeze the draft's wire format.

## Reputation (concept)

Reputation is the long-term memory of the framework:

- Built from **decision history**: how often did this agent's actions get `ALLOW` vs. `STEP_UP` vs. `BLOCK`?
- **Portable across principals** in principle — an agent well-behaved for one institution carries signal for another — but portability requires shared, privacy-preserving reputation exchange, which is future work.
- **Decays and recovers**: recent behavior weighs more; sustained good behavior rebuilds trust after incidents.
- **Never the sole signal**: a stellar reputation does not excuse an action outside delegation or intent. Reputation informs identity risk; it does not override intent or action evaluation.

## The core principle

> **An authenticated agent is not automatically a trusted agent.**

Identity establishes WHO the agent is. It does not establish:

- WHAT the agent is allowed to do (that's delegation),
- WHAT it was intended to do (that's intent),
- WHETHER it is behaving well right now (that's behavior),
- WHETHER this action should be allowed (that's the decision).

And further, per the framework:

> **An authorized agent is not automatically authorized for every action.**
> **A valid authorization does not guarantee that the agent is behaving as intended.**

Identity is the foundation of the trust graph — every other evaluation hangs off knowing *which* agent you're evaluating. But it is one input among six, and a perfect identity score never compensates for a failed intent match.

## Relationship to existing identity systems

KATA does not replace authentication. It sits **above and alongside** existing identity and authorization standards, consuming their evidence:

- W3C Verifiable Credentials → agent attribute claims
- OAuth 2.0 / OpenID Connect → delegation-adjacent authorization evidence
- WebAuthn → principal authentication strength
- SPIFFE/SPIRE → workload cryptographic identity
- IETF Web Bot Auth → cryptographic authentication of the automated client (Q1)
- Visa Trusted Agent Protocol → RFC 9421 signatures and a registry key (`key_id`, `public_key`, `algorithm`), aligned with Web Bot Auth
- AGNTCY identity → ResolverMetadata `verification_method.public_key_jwk` and badge credentials

Web Bot Auth, Visa Trusted Agent Protocol, and AGNTCY identity answer Q1 only. They do not carry a purchase intent. See [interoperability.md](interoperability.md) and [research/standards.md](../research/standards.md#ietf-web-bot-auth). KATA remains standards-neutral: it converts identity evidence into a broader trust and risk decision.
