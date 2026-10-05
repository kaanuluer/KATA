# Standards Landscape

**Status: Concept / Open Design — not production ready.**

KATA does not replace existing identity or authorization standards. It operates **above and alongside** them, consuming their evidence and converting it into a broader trust and risk decision. This document surveys the relevant landscape and states how KATA relates to each.

KATA's stance is **standards-neutral**: where a credible standard exists, KATA consumes its evidence rather than inventing a parallel mechanism.

## Identity & credentials

### W3C Verifiable Credentials

- **What it covers:** A standard data model for cryptographically verifiable, tamper-evident claims about a subject, issued by an issuer and held by a holder.
- **How KATA relates:** The natural carrier for *agent attribute claims* — provider, model, version, audit status — and for delegation credentials. KATA would consume VCs as identity and delegation evidence, not re-specify them.

### SPIFFE / SPIRE (workload identity)

- **What it covers:** A standard framework for assigning cryptographic identities (SVIDs) to software workloads, with attestation of *what* is running *where*.
- **How KATA relates:** The strongest available answer to "prove this agent is who it claims to be, running where it claims to run." KATA's Identity module would treat SPIFFE-style attestation as high-quality provenance evidence.

### WebAuthn / FIDO2

- **What it covers:** Phishing-resistant public-key authentication for humans.
- **How KATA relates:** Strengthens the *principal* side of the graph — proof that the human who granted the delegation is really that human. Relevant to grant-time and `HUMAN_APPROVAL` ceremonies.

## Authorization

### OAuth 2.0

- **What it covers:** Delegated authorization: a client acts with scoped, revocable tokens on a resource owner's behalf.
- **How KATA relates:** Conceptually adjacent — OAuth is the closest existing model to "delegation." But OAuth scopes are coarse and static; KATA needs intent-aware, behaviorally-monitored, continuously-evaluated delegation. KATA consumes OAuth tokens as delegation *evidence* while adding the intent/behavior/action layers OAuth never had.

### OpenID Connect

- **What it covers:** Identity layer on top of OAuth 2.0 — who the user is.
- **How KATA relates:** Principal identity evidence. KATA does not compete with OIDC; it sits above it.

## Agent protocols (emerging)

### Agent-to-agent identity & messaging efforts

- **What it covers:** Emerging work on how agents identify each other, discover capabilities, and exchange structured messages (various industry and open-source efforts are active and evolving).
- **How KATA relates:** KATA needs *some* agent identity substrate to function — it does not prescribe which one. Any agent protocol that provides attributable identity and structured action proposals can feed the KATA evaluation model. Interoperability here is an open research area (see [KATA.md](../KATA.md#25-open-questions)).

### Emerging agentic payment frameworks

- **What it covers:** Industry efforts to let agents initiate payments safely (delegated payment credentials, agent-aware 3-D Secure flows, etc.).
- **How KATA relates:** These are the *transaction rails* KATA would protect. KATA is the trust layer above the rails: it decides whether the agent should be making *this* payment, while the payment framework executes it.

## Payment authentication standards

- **What it covers:** 3-D Secure / EMV 3DS, tokenization, and related standards that authenticate payers and secure card transactions.
- **How KATA relates:** Transaction-level evidence. A 3DS challenge result is an input to the transaction-risk component — it says the *payment instrument* is legitimate, not that the *agent's action* matches intent. KATA adds the missing layer.

## What KATA deliberately does not standardize (yet)

- The cryptographic format of delegation tokens.
- The exact intent schema (a draft exists in [`schemas/`](../schemas/); formalization is future work).
- The wire protocol for exchanging trust decisions between institutions.
- Reputation exchange formats and privacy-preserving reputation protocols.

These are intentionally left open for community design — standardizing too early, before the threat model and use cases are validated, would be worse than standardizing late.

## Disclaimer

KATA is an independent open framework and is **not affiliated with** W3C, Google, Visa, Mastercard, OpenAI, or any other organization unless explicitly stated otherwise. References to standards above are descriptive only.
