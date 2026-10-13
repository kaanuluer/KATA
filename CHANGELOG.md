# Changelog

## 2026-10-13

A Vercel service in [`service/`](service/) hosts the revocation pull list, the signed push webhook, the transparency log, `/.well-known/kata-keys.json`, and a Frankfurter daily FX stub. Neon Postgres is the storage integration. Secrets stay in the Vercel project. The FX request sends a `kata-service` user agent and uses `https://api.frankfurter.dev/v1`. The same app serves an English page at `/` with a sample intent check and live views of the list, keys, and log.

## 2026-10-13

Kaan decided the remaining open points on the intent agreement.

- KATA produces the canonical confirmation text and its hash. The wallet or bank app displays that text and collects the signature. The verifier checks the signed hash against the text KATA produced. Another language is canonical only through a renderer registered on both sides.
- The spend ledger is hash-chained. Every authorization check carries the head hash and the sequence. A lower sequence is a deny. A replica older than 60 seconds, unless that window is changed, steps up. That age is the replica's sync time.
- When several intents are live and the action names none, one matching intent is selected. More than one match steps up. None match is a deny.
- Revocation in this version is a pull list cached for 5 minutes, a signed push webhook, and an append-only transparency log with a signed Merkle head. The library does not open a socket.
- A ceiling for any merchant and any category is off by default. When it is on, amounts convert into one reference currency (USD unless changed) with a pluggable daily FX rate.
- Institution keys are published at `/.well-known/kata-keys.json` and on a KATA allowlist. Rotated keys stay trusted for a grace period. The default grace is 7 days, because no duration was set.
- ES256 verifies beside Ed25519. The mandate names the algorithm.

## 2026-10-13

Kaan's answers on the intent agreement are now the spec.

- The agreement is stored inside the delegation. One delegation may hold several live intents. A child intent may be narrower than the parent set, and the sum of the cumulative slices cannot exceed the parent total.
- KATA holds the spend ledger on the agreement. A missing ledger is a deny. The per-transaction ceiling stays separate from that total.
- The principal's signature activates the agreement. The confirmation may use any language. A later entry the same day limits that to a registered canonical renderer. Only that principal can revoke. A price miss blocks the charge and does not revoke the grant. `P1M` stays thirty days. A missing expiry or ceiling asks for approval. A named revocation endpoint that was not checked steps the verdict down; a mandate with no endpoint does not step up for that reason.
- Version 1 stays major units and Ed25519, signed by the principal.

## 2026-10-12

Intent agreement, the machinery for KATA's third question.

- [docs/intent-agreement.md](docs/intent-agreement.md) specifies the signed intent mandate, the agreement lifecycle, the action check (`ALLOW`, `STEP_UP`, `DENY`), the threat controls, and how AP2, Verifiable Intent, OAuth, RAR, and GNAP sit beside it. KATA's schemas stay authoritative.
- [schemas/intent-mandate.json](schemas/intent-mandate.json) and [schemas/agreement.json](schemas/agreement.json). `intent.maximum_amount` stays the per-transaction ceiling. Cumulative and frequency limits are separate because they need a ledger.
- [`reference/python`](reference/python) signs a mandate with Ed25519, verifies it, evaluates an action, and revokes or expires the agreement. Tests and `examples/purchase_check.py` cover an in-scope purchase and an out-of-scope one. No risk score and no behavior model. Not production ready.

## 2026-10-12

README now states what is core and what is optional. An implementation needs the four questions, the intent and delegation schemas, and the decision outcomes. Use-case examples (payments, MCP or tool calls, checkout) are profiles. Sardine, Darwinium, and AgentCommerceBench are related work: they position KATA and do not extend it.

Darwinium's press release of 8 October 2026 is that related-work entry. Intent Intelligence infers intent from behavior (Journey Transition Probability on the order and timing of steps; MCP Protection links tool calls to the journey, checks agent credentials, and can step up before a payment). Darwinium reports that about one in four agentic transactions on its network self-declare. KATA records a signed intent and measures behavior against it. Under Q4, MCP tool-call sequences and aggregate drift across many requests are named as example signal sources. No new question, layer, or schema.

## 2026-10-12

KATA's docs were updated from a reading of Sardine's public report *[Rethinking Fraud Prevention for Agentic Commerce](https://www.sardine.ai/whitepapers/rethinking-fraud-prevention-for-agentic-commerce)* (2026). No schema or example changed. Nothing in the update is a measured result.

- Mapped Sardine's four Know Your Agent responsibilities onto Q1–Q4. Noted where KATA asks for a signed delegation and a signed structured intent, and where that record is evidence in a first-party "I didn't authorize this" dispute.
- Extended the threat model: a compromised AI application account as an upstream account-takeover path (verification succeeds, and the outcome is still fraud); agent spoofing; undeclared automation, with bot detection running alongside KATA; authorized agents acting inside their authority toward an illegitimate outcome; merchant, first-party, and third-party typologies in agentic flows.
- Cited [IETF Web Bot Auth](https://datatracker.ietf.org/wg/webbotauth/about/) as the emerging standard Visa and Mastercard agentic protocols use for agent authentication.
- Described segmented scoring and monitoring for agentic traffic, configurable `STEP_UP` thresholds (including per-session re-verification such as 3-D Secure), and the ways device and behavior signals degrade.
- Recorded the liability asymmetry: trust along the chain is transitive, and liability is not, across the user, the AI provider, the merchant, the PSP or acquirer, the network, and the issuer.
