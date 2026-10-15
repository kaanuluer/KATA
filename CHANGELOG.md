# Changelog

## 2026-10-15

A verify under 5 does not let a report affect the score. A verify under 100 weighs a quarter unless the agent has two counterparties and the link is at least a day old. A verify of 100 or more still weighs in full.

An operator with 90 days of clean history can reach `operator_established` from a key binding alone, which sits between key-bound and operator-verified. The settled-credit cap stays 25 until an agent has three external counterparties and real external volume, and then it scales with that volume.

Velocity limits now follow the action's segment and the agent's own history. Shopping, travel, treasury, and assistant use tighter daily windows, a day that jumps past three times the agent's median steps up, and so does a cash-out after a quiet week or a recent settled-credit rise.

Ring detection now discounts settled credit inside a strongly connected component of any length, when organizations share a signal, and when a cluster of at least three organizations keeps 80% of its transaction volume inside the cluster.

Re-registration links a denied agent across a new operator organization when a device, key, payment-instrument, timing, or evidence-hash signal matches, and a revoked, suspended, or fraud-reported agent stays linkable for 180 days. The new agent inherits that negative history with a 30-day half-life (`INHERITED_HISTORY`), in addition to the flat penalty while the 14-day window is still open.

The individual portal lists the disputes a principal has filed, and each agent card shows the assurance level, the score, and the risk complement. Revoke and dispute were already on the portal API.

Consortium members can record a key fingerprint and ask whether enough other members have seen it. The sighting stores the fingerprint only. `POST /v1/consortium/match` returns `matched: true` and the other-member count when that count reaches `GAB_CONSORTIUM_MATCH_THRESHOLD` (default 2). Below the threshold the count is omitted. The response does not name the other members. `004_consortium.sql` adds the tables. This match is exact. It is not a private set intersection, and it does not share reports.

`GET /v1/score-model` publishes the agent score weights as `gab-score-1`. `risk` on an agent is `1000 - score`. Individuals are not scored. `GAB_SCORE_WEIGHTS` can replace a weight for calibration. Invalid JSON or an out-of-range value is a configuration error. This version does not fit the weights from outcomes.

Identity proofing caps the points for a verification claim. Registration records a key binding. `operator_verified` counts only with an operator evidence hash, and `institution_attested` counts only with a wallet or bank evidence hash. `assurance_level` is the level the score uses. `verification_level` stays the claim. `POST /v1/agents/{agent_id}/proofing` files the hash. `GAB_REQUIRE_PROOFING` defaults on and does not follow `GAB_DEFENSES`. `003_proofing.sql` stores the rows. The demo seed files both higher proofs so `shopper-01` remains institution-attested at 724 after the sample chargeback. The hash is not confirmed by an outside issuer, and the service does not collect a government identifier.

`/simulation` publishes the synthetic stress test of the trust score. Every figure on that page is simulated test data, read from `service/kata_service/static/simulation-results.json`, with the charts shipped beside it.

The bureau score now requires a recorded verify before a report counts, discounts young reporters and reporters with upheld disputes, caps settled-activity credit, drops settled credit inside a short closed loop, steps up when a daily count or amount window is exceeded, and carries a penalty when a new agent matches a recently denied one. An open dispute against a young reporter holds the negative points until review. `GAB_DEFENSES=0` turns the set off. `002_defenses.sql` stores interactions, identity links, and optional device or key signals. `python3 -m kata_service.synthetic_score` prints a small labeled before/after.

## 2026-10-13

The bureau migration ships inside the installed package (`kata_service/migrations/001_bureau.sql`). `POST /v1/admin/seed-demo` writes the public demo into the live database when the bearer is `GAB_ADMIN_TOKEN` and `GAB_ALLOW_DEMO_SEED=1`. It does not require `GAB_DEMO`, and a second call does not insert another copy.

Global Agent Bureau now runs on the KATA service. Organizations authenticate with hashed API keys, the registry binds an agent key to a pseudonymous principal, stored intents are checked by `POST /v1/verify`, and participants file incidents, inquire with a purpose code, and subscribe to signed alerts. The trust score is a rule-based 0–1000 value with reason codes. Individuals sign in with a magic link. Requirements are in [docs/gab-requirements.md](docs/gab-requirements.md). The home page, `/dashboard`, and `/portal` use the Global Agent Bureau wordmark. Storage stays on the existing Neon `DATABASE_URL`. Supabase is not used.

The repository license changed from Apache-2.0 to the PolyForm Noncommercial License 1.0.0. Commercial use requires a separate license from Kaan Uluer. Versions published before this change were released under Apache-2.0 and remain available under those terms. This change applies from this commit forward. Third-party projects cited in the docs, including AgentCommerceBench, keep their own licenses.

A Vercel service in [`service/`](service/) hosts the revocation pull list, the signed push webhook, the transparency log, `/.well-known/kata-keys.json`, and a Frankfurter daily FX stub. Neon Postgres is the storage integration. Secrets stay in the Vercel project. The FX request sends a `kata-service` user agent and uses `https://api.frankfurter.dev/v1`. The same app serves an English page at `/` with a sample intent check and live views of the list, keys, and log. The page uses the teal seal and KATA wordmark. `/history` repeats the repository timeline. `/docs` renders the design doc, the delegation model, the intent model, the threat model, the JSON schemas, and an API reference. FastAPI's generated OpenAPI page is `/docs/openapi`.

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
