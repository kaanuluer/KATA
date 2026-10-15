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
- **How KATA relates:** Conceptually adjacent — OAuth is the closest existing model to "delegation." But OAuth scopes are coarse and static; KATA needs intent-aware, behaviorally-monitored, continuously-evaluated delegation. KATA consumes OAuth tokens as delegation *evidence* while adding the intent/behavior/action layers OAuth never had. RFC 9396 Rich Authorization Requests can carry a KATA intent as `authorization_details`. The intent schema stays KATA's. See [docs/intent-agreement.md](../docs/intent-agreement.md).

### GNAP (RFC 9635)

- **What it covers:** Grant negotiation: a client asks an authorization server for access, the user may interact, and the resulting grant is bound to a key.
- **How KATA relates:** The negotiate-then-grant loop is the same shape as an intent agreement's clarify-then-accept. A GNAP token is delegation evidence. GNAP access rights are not a KATA ceiling, a price band, or a behavior check. The signed mandate in [docs/intent-agreement.md](../docs/intent-agreement.md) stays the authority object.

### OpenID Connect

- **What it covers:** Identity layer on top of OAuth 2.0 — who the user is.
- **How KATA relates:** Principal identity evidence. KATA does not compete with OIDC; it sits above it.

## Agent protocols (emerging)

### Agent-to-agent identity & messaging efforts

- **What it covers:** Emerging work on how agents identify each other, discover capabilities, and exchange structured messages (various industry and open-source efforts are active and evolving).
- **How KATA relates:** KATA needs *some* agent identity substrate to function — it does not prescribe which one. Any agent protocol that provides attributable identity and structured action proposals can feed the KATA evaluation model. Interoperability here is an open research area (see [KATA.md](../KATA.md#25-open-questions)).

### IETF Web Bot Auth

- **What it covers:** The [Web Bot Auth working group](https://datatracker.ietf.org/wg/webbotauth/about/) (`webbotauth`) standardizes cryptographic authentication of automated clients — crawlers, and AI agents acting for end users — to sites built for humans. Current work signs requests with HTTP Message Signatures ([RFC 9421](https://www.rfc-editor.org/rfc/rfc9421)) and identifies the operator by a published key directory. The site checks a signature. It does not have to infer a bot from IP address or User-Agent. The working group is active. The signature protocol (`draft-ietf-webbotauth-httpsig-protocol`) is an Internet-Draft, not an RFC.
- **Who uses it in commerce:** Visa Trusted Agent Protocol and Mastercard Agent Pay use Web Bot Auth as the agent-authentication layer. That is how Cloudflare describes the collaboration, how Mastercard describes Agent Pay acceptance, and how Sardine's 2026 report *[Rethinking Fraud Prevention for Agentic Commerce](https://www.sardine.ai/whitepapers/rethinking-fraud-prevention-for-agentic-commerce)* describes both schemes. Shopify's WebMCP checkout path also has agents identify via Web Bot Auth.
- **How KATA relates:** Q1 evidence. A verified signature says the caller is a declared agent of a known operator, which is what makes straightforward agent spoofing expensive. The signature does not carry a purchase intent. A client that omits it is invisible to this control; bot detection stays in front of KATA for that undeclared traffic. KATA consumes the verification result and does not adopt the draft's wire format. See [docs/agent-identity.md](../docs/agent-identity.md).

### Agentic commerce & payment protocols (emerging)

Industry efforts to give agents signed, credentialed identity and safe payment rails. KATA's stance: these are the *transaction rails and identity substrates* KATA protects and consumes. KATA is the trust layer above the rails — it decides whether the agent should be making *this* payment (*is the agent legitimate, and does this action match the grant?*) — while these protocols execute it. KATA stays neutral and interoperable across all of them.

#### Universal Commerce Protocol (UCP)

- **What it covers:** Open-source commerce standard (Apache 2.0; announced January 2026 by Google, co-developed with Shopify, Etsy, Wayfair, Target, Walmart; 20+ endorsers including Visa, Mastercard, Stripe, Adyen, Amex). Standardizes the full shopping journey for AI agents: capability discovery via `/.well-known/ucp` manifests, checkout sessions (cart, totals, `ready_for_complete` state), discounts, fulfillment, order management, post-purchase. The merchant remains merchant of record. Composable with AP2 (payments), A2A and MCP (transports).
- **Trust-relevant primitives:** `UCP-Agent` profile header + `request-signature` (agent identity evidence); Identity Linking via OAuth 2.0 — the agent acts on the buyer's behalf without holding credentials (delegation evidence, e.g. scope `dev.ucp.shopping.checkout`); tokenized payments; verifiable credentials; cryptographic proof of user consent on authorizations.
- **How KATA relates:** UCP standardizes the *commerce* layer but defines no trust decision. Its checkout session is a structured, machine-readable **action object** — the ideal pre-execution evaluation point for KATA (evaluate at `ready_for_complete`: does this checkout match the principal's intent?). Its agent headers and OAuth identity-linking are **identity and delegation evidence** KATA consumes. See [examples/ucp-checkout/](../examples/ucp-checkout/) for a worked evaluation.
- **Shopify: UCP in production.** Shopify co-developed UCP and is its largest live deployment. Agentic Storefronts (Storefront Catalog MCP migrated to UCP in April–May 2026; Universal Cart for multi-item agentic checkout; on by default for eligible stores) serve ChatGPT, Perplexity, Microsoft Copilot, and Google Gemini/AI Mode, with agent orders landing in Shopify admin like any channel order. In September 2026 Shopify extended WebMCP to checkout (`get_checkout`, `update_checkout`, `complete_checkout`, including Shop Pay) so browser-based agents can complete purchases with buyer authorization — with protocol-level trust controls that mirror KATA concepts: changed totals require asking again (intent re-verification), agents cannot enter new card details (constrained action space), 3DS hands control back to the buyer (step-up), and agents identify via Web Bot Auth (agent identity signal; see [IETF Web Bot Auth](#ietf-web-bot-auth) above). Shop Pay operates as a payment handler inside UCP's modular payment architecture.

#### Agent Payments Protocol (AP2)

- **What it covers:** The payment-authorization companion to UCP. Current text is **v0.2** (open and closed Checkout Mandate, open and closed Payment Mandate). The names Intent Mandate and Cart Mandate are **v0.1** (`IntentMandate`, `CartMandate`, `PaymentMandate` in `mandate.py` at commit `e66fc0b`). v0.2 does not use those names. Field mapping, the unit conversion (integer minor units → KATA major units), and where `POST /kata/evaluate` sits are in [docs/interoperability.md](../docs/interoperability.md).
- **How KATA relates:** A verified mandate is Q2/Q3 evidence. AP2 does not score behavior, compare a quote to a charge, or return `REVOKE` / `QUARANTINE`. The worked v0.2 sample is [examples/ap2-checkout/](../examples/ap2-checkout/). [examples/ucp-checkout/](../examples/ucp-checkout/) is an earlier sketch whose property names are not spec fields.

#### Other efforts

- **Visa Trusted Agent Protocol** — RFC 9421 agent signatures and a key registry, aligned with Web Bot Auth. Q1 evidence. Brief map in [docs/interoperability.md](../docs/interoperability.md).
- **Verifiable Intent** (Mastercard-maintained, draft v0.1) — SD-JWT chain credential provider → user → agent, with amount range, line items, and merchant constraints. Field map and worked example: [docs/interoperability.md](../docs/interoperability.md), [examples/verifiable-intent/](../examples/verifiable-intent/).
- **AGNTCY identity** — agent id, ResolverMetadata, and badge verifiable credentials. Q1 only. Same interoperability note.
- **Stripe Agentic Commerce Suite** — agent-oriented commerce infrastructure; transaction evidence.

## Payment authentication standards

- **What it covers:** 3-D Secure / EMV 3DS, tokenization, and related standards that authenticate payers and secure card transactions.
- **How KATA relates:** Transaction-level evidence. A 3DS challenge result is an input to the transaction-risk component — it says the *payment instrument* is legitimate, not that the *agent's action* matches intent. KATA adds the missing layer.

## What KATA deliberately does not standardize (yet)

- The cryptographic format of delegation tokens. A reference signature for the **intent mandate** (Ed25519 or ES256 JWS, canonical JSON) is drafted in [docs/intent-agreement.md](../docs/intent-agreement.md). It is a reference, not a claim that the wire format is finished.
- The exact intent schema (a draft exists in [`schemas/`](../schemas/); the signed mandate embeds it).
- The wire protocol for exchanging trust decisions between institutions.
- Reputation exchange formats and privacy-preserving reputation protocols.

These are intentionally left open for community design — standardizing too early, before the threat model and use cases are validated, would be worse than standardizing late.

## Disclaimer

KATA is an independent open framework and is **not affiliated with** W3C, Google, Visa, Mastercard, OpenAI, or any other organization unless explicitly stated otherwise. References to standards above are descriptive only.
