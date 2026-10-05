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

### Agentic commerce & payment protocols (emerging)

Industry efforts to give agents signed, credentialed identity and safe payment rails. KATA's stance: these are the *transaction rails and identity substrates* KATA protects and consumes. KATA is the trust layer above the rails — it decides whether the agent should be making *this* payment (*is the agent legitimate, and does this action match the grant?*) — while these protocols execute it. KATA stays neutral and interoperable across all of them.

#### Universal Commerce Protocol (UCP)

- **What it covers:** Open-source commerce standard (Apache 2.0; announced January 2026 by Google, co-developed with Shopify, Etsy, Wayfair, Target, Walmart; 20+ endorsers including Visa, Mastercard, Stripe, Adyen, Amex). Standardizes the full shopping journey for AI agents: capability discovery via `/.well-known/ucp` manifests, checkout sessions (cart, totals, `ready_for_complete` state), discounts, fulfillment, order management, post-purchase. The merchant remains merchant of record. Composable with AP2 (payments), A2A and MCP (transports).
- **Trust-relevant primitives:** `UCP-Agent` profile header + `request-signature` (agent identity evidence); Identity Linking via OAuth 2.0 — the agent acts on the buyer's behalf without holding credentials (delegation evidence, e.g. scope `dev.ucp.shopping.checkout`); tokenized payments; verifiable credentials; cryptographic proof of user consent on authorizations.
- **How KATA relates:** UCP standardizes the *commerce* layer but defines no trust decision. Its checkout session is a structured, machine-readable **action object** — the ideal pre-execution evaluation point for KATA (evaluate at `ready_for_complete`: does this checkout match the principal's intent?). Its agent headers and OAuth identity-linking are **identity and delegation evidence** KATA consumes. See [examples/ucp-checkout/](../examples/ucp-checkout/) for a worked evaluation.

#### Agent Payments Protocol (AP2)

- **What it covers:** The payment-authorization companion to UCP. Uses W3C Verifiable Digital Credentials ("mandates") as cryptographically signed contracts:
  - **Cart Mandate** (human-present): payer/payee, exact payment method, risk payload, line-item details, refund conditions — signed by the user (e.g., hardware-backed device key).
  - **Intent Mandate** (human-not-present): pre-authorization for autonomous shopping — payer/payee, chargeable methods, risk payload, **shopping intent (categories, SKUs, budget limits)**, prompt playback, TTL.
  - **Payment Mandate**: minimal credential for issuers — agent-presence indicator, modality, fraud signals.
- **How KATA relates:** The **Intent Mandate is the closest industry realization of KATA's structured intent** — budget limits, categories, and TTL as machine-readable constraints. KATA's intent-schema work should explicitly map to it. But AP2 stops at *capturing* authorization: nothing in the stack *evaluates* whether the resulting checkout matches the mandate, monitors the agent's behavior across sessions, or makes graduated risk decisions — that is KATA's layer. AP2's separation of principal / agent / issuer with non-repudiable audit trails pairs naturally with KATA's explainable decisions.

#### Other efforts

- **Visa Trusted Agent Protocol** — signed, credentialed agent identity for commerce; identity evidence for KATA.
- **Mastercard Agent Pay (with Verifiable Intent)** — carries the user's grant with the transaction; track alongside AP2's Intent Mandate for intent-schema direction.
- **Stripe Agentic Commerce Suite** — agent-oriented commerce infrastructure; transaction evidence.

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
