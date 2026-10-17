# Global Agent Bureau requirements

Global Agent Bureau (GAB) is an independent agent bureau and technology company. KATA remains the framework that answers who the agent is, who authorized it, what it was authorized to do, and whether this action still matches. This document describes the bureau service in this repository. It matches the behavior of the code in `service/`.

The bureau does not produce consumer credit reports and it does not score individuals. Product copy does not use credit-bureau wording.

Storage is one Postgres database, the Neon database already connected on Vercel through `DATABASE_URL`. Supabase is not used. No Supabase project and no Supabase environment variables are required.

## 1. User roles

| Role | How they sign in | What they can do |
|---|---|---|
| Admin | `GAB_ADMIN_TOKEN` bearer | Create organizations. Review disputes. All scopes. |
| Agent operator | API key or organization email | Register agents, store intents, verify, report, subscribe, manage keys. Default scopes omit `inquire`. |
| Wallet or bank/issuer | API key or organization email | Inquire, verify, report, attest an agent to `institution_attested`, subscribe, manage keys. |
| Processor/PSP or merchant | API key or organization email | Inquire, verify, report, subscribe, manage keys. They cannot attest. |
| Individual principal | Magic-link email | See their agents, authorizations, inquiries, and incidents. Revoke an agent or an intent. File a dispute. |
| Anonymous | None | Home, history, docs, demo check, revocation pull, log read, published keys, FX, and magic-link requests. |

Organization types are `agent_operator`, `wallet`, `bank_issuer`, `processor_psp`, and `merchant`. Any other type is rejected.

## 2. Functional requirements and acceptance criteria

### 2.1 Organizations, API keys, rate limits, and audit

- An admin creates an organization with a name and a type.
- A key is issued to one organization. The response includes the raw token once, shaped `gab_{prefix}_{secret}`. The store keeps only the SHA-256 hash.
- List and rotate responses include the prefix, scopes, and key id. They do not include the hash or the raw token.
- Rotate revokes the old key and issues a new one. A revoked key receives 401.
- A caller from another organization that lists or rotates a key receives 404.
- A non-admin that creates an organization receives 403.
- Default scopes: operators get `registry:read`, `registry:write`, `verify`, `report`, `alerts`, `keys:manage`. Wallets and banks get those plus `inquire`. Other types get `registry:read`, `inquire`, `verify`, `report`, `alerts`, `keys:manage`.
- Every `/v1` request is counted toward a per-minute limit. The default is 120. Over the limit the response is 429 `{"error":"rate limit exceeded"}`. The subject is the hash of the bearer token, or the client host when there is no bearer.
- `POST /v1/verify`, `POST /v1/inquiries`, and `POST /v1/reports` also have their own per-minute caps, counted separately from the global cap. The defaults are 60, 30, and 10.
- After each `/v1` response the service writes an audit row: id, time, organization, key id, method, path, status, purpose code, agent id, and environment (`live` or `test`). The row does not include the Authorization header, the raw key, or an email address. `GET /v1/audit` returns that organization's rows for the key's environment. A live key sees live rows. A `gab_test_` key sees test rows. The individual portal does not read this log.

Acceptance: the tests in `service/tests/test_bureau.py` create an organization, reject a cross-tenant key list, reject a revoked key, reject a non-admin organization create, and reject a third call when the limit is 2 per minute.

### 2.2 Agent registry

- Only an agent operator registers an agent.
- The agent id matches `^[A-Za-z0-9._-]{1,80}$`.
- The public key is an Ed25519 or P-256 JWK. A private `d` parameter is rejected.
- The principal id is a pseudonym. The service does not ask for a name, address, or government identifier.
- Verification levels an operator may set are `unverified`, `key_bound`, and `operator_verified`.
- A wallet or bank may set `institution_attested` through `POST /v1/agents/{id}/attest`. An operator who calls that route receives 403.
- Status is `active`, `suspended`, or `revoked`. The principal portal can revoke and cannot suspend.
- Lookup is by agent id or by key fingerprint.
- The owning operator, the admin, and the principal's portal session receive `principal_id`. Other tenants do not.
- Registration appends a transparency-log entry whose body is the agent id, fingerprint, status, and a record hash.

Acceptance: a merchant lookup omits `principal_id`, a fingerprint lookup returns the agent, a wallet attestation sticks, and an operator attestation is 403.

### 2.3 Intents and verify

- The operator stores a signed KATA agreement for an agent they operate.
- The agreement must be active, name that agent, name the registered principal, and carry the registered agent key.
- The principal public key inside the signed mandate is bound on first store. A later agreement signed by a different principal key is rejected.
- `POST /v1/verify` evaluates the payment with the reference library, including cumulative limits and the named intent when `intent_id` is set. Several mandates inside one agreement are the sub-intents.
- An allowed verify records an interaction for the caller's organization, or for `counterparty_org_id` when that field names an organization. That interaction is what lets a later report affect the score.
- When velocity limits are on, an allow that would exceed the UTC-day count (default 25) or the same-currency amount (default 15,000) becomes `DENY` with `kata_decision` `BLOCK` and `VELOCITY_COUNT` or `VELOCITY_AMOUNT`, and does not append the ledger. A score of 750 or more triples both windows. A re-registration link halves them for 14 days. An action `segment` of shopping, travel, treasury, or assistant uses the tighter of that cap and its segment window. A burst above the agent's own history, or a cash-out after a quiet week or a recent settled-credit rise, is `DENY` with `VELOCITY_BURST` or `VELOCITY_CASHOUT`.
- An inactive agent is `DENY` / `BLOCK` / `AGENT_NOT_ACTIVE`.
- No active agreement is `DENY` / `NO_ACTIVE_AGREEMENT`.
- More than one active agreement and no `agreement_id` is `STEP_UP` / `AGREEMENT_NOT_SELECTED`.
- `ALLOW` appends the spend to the agreement ledger and saves it.
- A library `KataError` is HTTP 400.

Acceptance: 1300 CAD against a 1500 ceiling and a 2000 cumulative cap is `ALLOW`; a further 900 is `DENY`; 4200 is `DENY`.

### 2.4 Incidents and reciprocity

- Kinds are `transaction_outcome`, `fraud_incident`, `chargeback`, and `policy_violation`.
- `evidence_hash` matches `^sha256:[0-9a-f]{64}$`.
- Optional outcome is `settled`, `loss`, or `cleared`.
- The same reporter, agent, kind, and evidence hash is 409.
- Each organization has a daily cap (default 20). Over the cap is 429 `daily report cap reached`.
- With the default defenses, a report is rejected with 400 unless that reporter has a recorded allowed verify with the agent that meets the link minimum. The report is not stored. Optional `action_id` must be one of those verifies. A stored report has `counts: true`.
- The operator of the agent, and any organization that has filed at least one report, receives full report bodies. Everyone else with `report` scope receives counts only.
- A new incident appends a transparency-log entry of hashes and ids, not the free-text summary, and notifies subscribers.

Acceptance: a stranger sees the count and not the summary; the reporter sees the summary; a duplicate is 409.

### 2.5 Inquiry

- `purpose_code` is required and is one of `payment_authorization`, `account_opening`, `fraud_investigation`, `dispute_resolution`, `ongoing_monitoring`, `agent_onboarding`.
- The response includes agent identity (id, status, verification, fingerprint, algorithm, operator name), active authorization summaries, revocations, incident counts, and the trust score with reason codes.
- Contributors also receive recent `{report_id, kind, evidence_hash, created_at}`.
- The response does not include email or `principal_id`.
- Every inquiry is stored and is visible to the principal in the portal, with the inquiring organization's name, type, purpose, and time.

Acceptance: a missing purpose is 400; a completed inquiry appears on `GET /v1/portal/inquiries` without the principal's email.

### 2.6 Trust score v1

- The score is an integer from 0 to 1000 for an agent. There is no score endpoint for a person. `risk` on an agent is `1000 - score`. It is the same model, read from the other end.
- Cold start, with no contributing report, starts at 500 and adds identity points: unverified 0, key_bound 40, operator_verified 120, institution_attested 200, plus 80 when the operator is active and minus 40 when the operator is not. The first reason code is `COLD_START` when nothing has been reported.
- Report weights: bank_issuer and processor_psp 1.0, wallet 0.8, merchant 0.7, agent_operator 0.4. A report filed by the agent's own operator is multiplied by 0.25.
- The same `(kind, evidence_hash)` keeps the highest weight.
- Impacts, times weight, rounded: fraud −120, chargeback −80, policy −40, settled +8, loss −30.
- A resolved dispute with outcome `upheld` drops that report from the score (`DISPUTE_UPHELD`). Outcome `partial` halves the weight.
- At most four reason codes are returned, ordered by absolute points, skipping zeros. `COLD_START`, `DISPUTE_HOLD`, and `RING_DISCOUNTED` may appear with zero points.
- `trust_score` without a policy still uses that v1 formula, which is what the original unit test calls.
- The service passes `ScorePolicy` from settings. `GAB_DEFENSES=0` turns the extra rules off. Each rule has its own flag, listed in the environment table.

Acceptance: the unit test keeps the bank's fraud impact over a duplicate merchant report, and an upheld dispute removes `FRAUD_INCIDENT`.

The service does not pass the raw claim into that formula when proofing is on. It passes `assurance_level` from section 2.6.2.

### 2.6.1 Defenses around the score

These rules are on unless `GAB_DEFENSES=0` or the matching flag is `0`.

- Transaction link (`GAB_REQUIRE_REPORT_LINK`): a report with no allowed verify, or with a verify under `GAB_LINK_MIN_AMOUNT` (5), is rejected and not stored. A verify of at least `GAB_LINK_FULL_AMOUNT` (100) counts in full. A smaller qualifying verify counts at `GAB_LINK_THIN_WEIGHT` (0.25) unless the agent has `GAB_LINK_MIN_COUNTERPARTIES` (2) counterparties and the link is at least `GAB_LINK_MIN_AGE_DAYS` (1) old.
- Reporter reputation (`GAB_REPORTER_REPUTATION`): an organization younger than `GAB_NEW_REPORTER_DAYS` (30), or with no creation time, is multiplied by `GAB_NEW_REPORTER_WEIGHT` (0.3). Each upheld dispute against that reporter halves the weight again, up to eight times. `GAB_REPORT_CONSISTENCY` keeps that weight and then multiplies a negative report by 0.5 when the same reporter also has settled activity for that agent, by 0.4 when that reporter has at least 3 negative reports aimed at 1 or 2 operators, and by 0.5 when at least 3 reporters reused the same evidence hash.
- Positive cap (`GAB_POSITIVE_CAP`): settled points diminish for repeat reports from the same reporter, then stop at `GAB_SETTLED_CAP_PER_REPORTER` (16) and `GAB_SETTLED_CAP_TOTAL` (25). `GAB_SETTLED_CAP_SCALES` raises that total by 5, and the per-reporter cap by 2, for each 500 of external volume once the agent has at least 3 counterparties and 500 of external volume. Each of those counterparties must have at least 100 with the agent. The raise stops after 8 steps. A ring with no external volume keeps the base cap.
- Velocity (`GAB_VELOCITY`, `GAB_VELOCITY_ADAPTIVE`): the static windows above still apply, and exceeding one is `DENY`. Segment windows are shopping 8 / 1,000, travel 6 / 2,500, treasury 4 / 5,000, and assistant 10 / 800. `VELOCITY_BURST` denies when today exceeds `GAB_VELOCITY_BURST_MULTIPLE` (3) times the median of at least three earlier days. `VELOCITY_CASHOUT` denies at `GAB_VELOCITY_CASHOUT_AMOUNT` (500) after `GAB_VELOCITY_QUIET_DAYS` (7), or after settled credit in the last 7 days when today also clears that multiple.
- Ring detection (`GAB_RING_DETECTION`): settled credit is dropped when the reporter and the agent's operator sit in the same strongly connected component, so a closed loop can be longer than four. Organizations that share a device, key, payment, timing, evidence, or `shared_signal` are treated as one node, which catches a one-way reporter. A group of at least `GAB_RING_MIN_CLUSTER` (3) organizations whose internal transaction volume is at least `GAB_RING_INTERNAL_RATIO` (0.8) of its total volume is discounted the same way. Filing the report rescores agents in that cluster. Reason code `RING_DISCOUNTED`. `005_org_signals.sql` stores the organization signals.
- Re-registration (`GAB_REREG_LINK`): a new agent is linked to a denied agent in three ways. The same operator matches for `GAB_REREG_LOOKBACK_DAYS` (14). A shared `device_signal`, `key_signal`, `payment_instrument`, `timing_signal`, or `proofing_evidence` matches across operator organizations for `GAB_REREG_SIGNAL_LOOKBACK_DAYS` (90). A revoked, suspended, or fraud-reported agent matches for `GAB_REREG_MALICIOUS_LOOKBACK_DAYS` (180), including the same operator after the 14-day window. The flat `IDENTITY_LINK` penalty is still `GAB_REREG_PENALTY` (80), or the deficit below 500, capped at 200, and it still expires after 14 days. `GAB_INHERIT_HISTORY` also copies that agent's negative reports onto the new score as `INHERITED_HISTORY`, decaying by half every `GAB_INHERIT_HALF_LIFE_DAYS` (30). Positive reports are not copied. The service does not collect a government identifier. Callers should pass a hash for a payment instrument or a timing pattern.
- Dispute hold (`GAB_DISPUTE_HOLD`): while a dispute is open or under review, a negative report from a young reporter does not reduce the score. Reason code `DISPUTE_HOLD`. Resolving the dispute removes the hold.

`/simulation` publishes one synthetic stress test, labeled `SYNTHETIC TEST DATA – not real customers`. The run is 10,000 synthetic agents and 100,000 synthetic transactions over 90 days. Against adaptive attackers, 73% of attempted fraud dollars are stopped and $0.71M is executed. When attackers do not know the rules, 78% is stopped and $0.68M is executed. Legitimate agents denied at day 90 are 0.15% and 0.16%. The numbers are read from `simulation-results.json`.

Acceptance: an unlinked chargeback is 400 and leaves the score unchanged; a linked chargeback from a young reporter is held while the dispute is open; a second allowed verify past a count cap of 1 is `DENY` / `VELOCITY_COUNT`; a new agent after a revocation carries `IDENTITY_LINK`.

### 2.6.2 Identity proofing

`GAB_REQUIRE_PROOFING` defaults on. It does not follow `GAB_DEFENSES`.

- `verification_level` stays the claim the operator or the wallet set.
- `assurance_level` is the level the score uses.
- Registration writes `key_binding`. The evidence hash is the key fingerprint.
- Optional `proofing_evidence` on registration is `sha256:` and 64 hex characters. It writes `operator_review` in the same call.
- `POST /v1/agents/{agent_id}/proofing` accepts `operator_review` from that agent's operator and `institution_attestation` from a wallet or bank. `key_binding` is not accepted on that route.
- With the gate on, `institution_attested` needs `institution_attestation`. Otherwise `operator_review` supports `operator_verified`. Otherwise, when `GAB_OPERATOR_HISTORY` is on, an active operator older than `GAB_OPERATOR_HISTORY_DAYS` (90) with no upheld dispute against its own reports supports `operator_established` (80 identity points) for an operator or institution claim. Otherwise a registered key supports `key_bound`. `unverified` stays `unverified`. A new operator does not get the established path.
- With the gate off, the claim is the assurance level.
- A proof row stores the hash, the method, the filing organization, and the time. It does not store a government identifier or a free-text statement. This version checks the hash format and does not ask an outside issuer to confirm it.
- The operator, the admin, and the principal can list those rows. Other tenants see `assurance_level` and not the hashes. The filing response includes the one row just written.
- The demo seed files an operator review and an institution attestation, so `shopper-01` stays `institution_attested` and the sample chargeback still lands at 724.

Acceptance: an `operator_verified` registration without `proofing_evidence` has `assurance_level` `key_bound` and score 620. An operator review raises that to `operator_verified` and 700. A wallet attestation without `institution_attestation` does not add the institution points. An operator cannot file `institution_attestation`.

### 2.6.3 Score model and calibration

`GET /v1/score-model` needs no credential. It publishes model version `gab-score-1`, the baseline, identity points, operator points, report points, and reporter weights. The body says subjects are agents, `individuals_scored` is false, and `risk` is `1000 - score`.

`GAB_SCORE_WEIGHTS` is optional JSON. It can replace those numbers and the model version. A value outside the documented range, or JSON that does not parse, sets the process configuration error and `/v1` returns 500, the same way a bad signing key does. Unknown JSON keys are ignored. Nested `identity` and `reporter_weights` objects override those tables. Report points use the names `fraud_incident`, `chargeback`, `policy_violation`, `settled`, and `loss`.

The hook is for calibration. This version does not fit weights from outcomes, and it does not store a labeled dataset for that fit.

Acceptance: `GET /v1/score-model` returns `gab-score-1` and fraud impact `-120` with no environment override. A policy whose fraud impact is `-100` makes one bank fraud report worth `-100` points. An agent response includes `risk` equal to `1000 - score`.

### 2.7 Alerts

- A participant with `alerts` subscribes to an agent and a webhook URL.
- `https` is required. `http` is rejected, and so is an `https` URL whose host is a loopback name.
- Events are revocation, a new incident, and a score drop of 50 points or more.
- The body is `{at, kata_bureau_alert: "1", alert, signature}`. `signature` is a flattened JWS with `typ` `kata-bureau-alert+jws`, signed by `KATA_LOG_SIGNING_SEED`.
- The inbound revocation-push verifier still uses `KATA_PUSH_NOTIFIER_JWK`, which is public only and cannot sign outbound alerts.
- Delivery uses a 3-second timeout. A failed delivery does not fail the revocation, report, or status change. The alert row records whether delivery succeeded.
- Demo and memory mode record the body in process instead of opening a socket.

Acceptance: revoking an agent after an https subscription stores a signed `kata_bureau_alert` body.

### 2.8 Individual portal

- `POST /v1/portal/magic-link` always returns `{"sent": true}`. A new email creates a new principal id. An email already bound to a principal keeps that principal. The binding cannot be moved to a different principal.
- `POST /v1/agents` accepts optional `principal_email`. That address is bound to the registered principal. If the address is already bound to another principal, the response is 409.
- Mail uses SMTP when `GAB_SMTP_HOST`, `GAB_SMTP_USER`, `GAB_SMTP_PASSWORD`, and `GAB_SMTP_FROM` are all set. The default port is 587 with STARTTLS. If any of those four is missing, no network mail is sent and the link is not printed. `GAB_PUBLIC_BASE_URL` is the origin in the link.
- The token is stored as a hash. The link lifetime is 15 minutes. The session lifetime is 12 hours.
- The development mailbox (`GAB_DEV_MAILBOX=1` or `GAB_DEMO=1`) keeps the latest link in memory. `GET /v1/dev/mailbox` is 404 when that flag is off.
- Organization magic links also always return `{"sent": true}` and send only when the email was registered in advance, so the response does not reveal whether the address exists.
- The portal lists the principal's agents with assurance level, authorizations, inquiries, incident reports, and disputes. It does not return a trust score, a risk figure, or score reasons, and it does not score the individual.
- A passkey can sign in. The email link remains. Registering a device is explicit. The individual can list devices and remove one with a fresh passkey assertion.
- Revoking an agent, revoking an intent, and filing a dispute each require that same passkey assertion.
- Push registration is refused unless `consent` is true. Approval notices stay off unless `GAB_STEP_UP_APPROVAL` is set. The push sentence is fixed: `an agent is waiting for your approval, open to review`. It does not include a merchant, an amount, or an agent name. An approval is single-use, bound to one action, and short-lived. Approve and reject use the same passkey assertion as revoke and dispute.
- The portal page states what is stored: the email and principal id, the public half of each passkey, a push address only after consent, and a short-lived approval only while that flow is on.

Acceptance: after the login row is bound to the registered principal, the portal lists the agent, the inquiry, and the report, and a principal revoke makes verify return `AGENT_NOT_ACTIVE`.

### 2.9 Disputes

- A principal files a dispute against a report on their agent. Status starts at `open`.
- Admin review sets `under_review` or `resolved`. A resolved dispute requires outcome `upheld`, `rejected`, or `partial`.
- `upheld` excludes the report from the score and rescores the agent.
- Filing the dispute rescores the agent. With the dispute hold on, an open dispute against a young reporter pauses that report's negative points until an admin resolves it. There is no review deadline.

Acceptance: an upheld policy-violation dispute leaves the score greater than or equal to the score before review.

### 2.10 Transparency log

- Registrations, revocations, and incidents append to the existing hash-chained Merkle log.
- Log bodies carry ids and hashes. They do not carry email, report summaries, or `principal_id`.

### 2.11 Web UI

- `/` is the Global Agent Bureau home. It keeps the four KATA questions, the sample sign-and-check, the live revocation list, published keys, and the tree head. The stress-test section states the same synthetic headline as `/simulation` and links there. The nav also links to the dashboard, portal, history, docs, and GitHub.
- `/simulation` publishes that one synthetic stress test. Every table and chart is labeled `SYNTHETIC TEST DATA – not real customers`. The numbers are read from `service/kata_service/static/simulation-results.json`. The five charts are the PNGs shipped beside that file. The page describes Global Agent Bureau as an agent bureau, names the PolyForm Noncommercial License 1.0.0, and links to globalagentbureau.com.
- The header mark is the single file `service/kata_service/static/gab-logo.svg`. Replacing that file replaces the mark.
- `/dashboard` signs in with an API key or an organization email and can register an agent, run an inquiry, file an incident, list alerts, manage keys, and, with the admin token, review disputes.
- `/portal` signs in with a magic link and shows agents, assurance level, score, risk, authorizations, inquiries, incidents, and the disputes the principal has filed.
- `/docs` renders this document. `/docs/api` and `/docs/openapi` describe the routes.
- The license line on each page is the PolyForm Noncommercial License.

### 2.12 Demo seed

- `GAB_DEMO=1` uses the memory repository even when `DATABASE_URL` is set, turns on the development mailbox, and seeds Harbor Agents, Northwind Wallet, Techstore, agent `shopper-01`, agreement `agr_demo`, one chargeback, and an https subscription.
- Public demo credentials, which must not be used in production: admin `gab-demo-admin`, operator `gab_demo_operator_public`, wallet `gab_demo_wallet_public`, merchant `gab_demo_merchant_public`, portal `principal@example.com`, organization email `ops@harbor.example`.
- `python3 -m kata_service.seed` applies the SQL migration to `DATABASE_URL`. `--demo` also inserts that data. Without `DATABASE_URL` the script exits and tells the operator to use `GAB_DEMO=1` for a local demo.
- `POST /v1/admin/seed-demo` inserts the same public demo rows into whatever repository the process is using, including Neon, without `GAB_DEMO`. The caller must send the `GAB_ADMIN_TOKEN` bearer. The route returns 403 `demo seed is disabled` unless `GAB_ALLOW_DEMO_SEED=1`. A second call keeps the same organizations, agent, agreement, chargeback, and subscription. The response lists the public demo keys and does not echo the admin token.
- The SQL files `kata_service/migrations/001_bureau.sql` through `005_org_signals.sql` are package data, so an installed copy can apply the schema. `002` adds interactions, identity links, agent signals, and an optional `action_id` on reports. `003` adds `gab_proofings`. `004` adds consortium members and sightings. `005` adds organization signals. `GAB_DEMO` is not required for that route and must stay unset on Vercel, because demo mode ignores `DATABASE_URL`.
- The public demo merchant is dated `2026-01-01T00:00:00Z`, and the seed records interaction `act_demo_laptop` before the sample chargeback, so that chargeback still counts at the merchant weight. The seed also records `operator_review` and `institution_attestation` for `shopper-01`.

### 2.13 Consortium sightings

Members can record that they have seen an agent key fingerprint, and they can ask whether other members have seen it. This is a sighting bit. It is not a shared feed of reports, scores, or identities.

- An admin adds a member with `POST /v1/admin/consortium/members` and an `org_id`. A second call returns the same membership.
- A member with `registry:read` records `POST /v1/consortium/sightings`. The body is the fingerprint only, `sha256:` and 64 hex characters. The same member and fingerprint is stored once.
- `POST /v1/consortium/match` counts other members who recorded that fingerprint. The caller is not counted.
- When that count is at least `GAB_CONSORTIUM_MATCH_THRESHOLD` (default 2), the response is `matched: true` and `other_member_count`.
- Below the threshold the response is `matched: false` and the count is omitted.
- The sighting table stores `member_id`, the fingerprint, and the time. It does not store an agent id, a principal id, an email, an organization name, or report text. The match response does not name the other members.
- A non-member receives 403. There is no route that lists every fingerprint.
- `004_consortium.sql` creates the two tables.

This version matches the exact fingerprint the caller already has. It does not run a private set intersection, and it does not hide the fact that a caller tested a particular fingerprint from that caller's own member record.

Acceptance: one other sighting stays `matched: false` with no count. A third member's sighting, so two others, returns `matched: true` and `other_member_count` 2. The match body has no organization name and no agent id.

## 3. Non-functional requirements

- The process is a FastAPI app. Vercel loads `app:app` from the repository-root `app.py`. Importing the module does not open Postgres. The bureau repository opens on the first `/v1` request.
- Tests run against the memory repository and do not need a network or a database.
- Postgres schema lives in `service/kata_service/migrations/001_bureau.sql` and is applied by `PostgresRepo` on first use. KATA tables remain the revocation list, log, tree head, and FX cache.
- Webhook delivery and mail sending are protocols. Tests use an in-memory sender. Production Postgres uses an HTTP sender for webhooks. Mail uses SMTP when the SMTP variables are set, and otherwise does not print the link.
- Decimal amounts in stored agreements round-trip through canonical JSON.

## 4. Security and privacy

- API keys and magic-link tokens and sessions are stored as SHA-256 hashes. Admin comparison uses `hmac.compare_digest`.
- Authorization failures across tenants are 404 for missing objects the caller does not own, and 403 for a missing scope or a forbidden role.
- Request bodies are JSON objects. Agent ids, emails, evidence hashes, purpose codes, and webhook URLs are checked before use.
- Audit rows, inquiry responses, and transparency-log bodies do not contain email addresses or raw credentials.
- The development mailbox returns the latest link, including the email, and is disabled unless the flag is on. Do not enable it in production.
- `GAB_DEMO=1` ignores the production database and installs public credentials. Do not set it on Vercel production.
- Outbound webhook URLs must be `https`, and the host must not be a loopback name.

## 5. Compliance notes

- The license is the PolyForm Noncommercial License 1.0.0. Commercial use needs a separate license from Kaan Uluer. Earlier published versions were Apache-2.0.
- Purpose limitation: an inquiry without a purpose code is rejected, and the purpose is stored on the inquiry the principal can see.
- Data minimization: evidence in the log is a hash. The principal id is a pseudonym. Email exists only on the login tables.
- The score covers agents and the operator's activity. It is not a score of a person and it is not a consumer credit report.
- Proofing evidence is a hash. The service does not collect a government identifier.
- Consortium sightings store a key fingerprint and a member id. Match results below the threshold omit the count and never name the other members.
- Product and interface copy does not describe GAB as a consumer credit reporting agency and does not use credit-bureau wording.
- Reciprocity limits full incident text to organizations that contribute reports, plus the operating organization and the principal.

## 6. Operations and SLOs

These are design targets for this version. They are not measured uptime or latency guarantees, and the service does not publish an error budget.

| Target | Value |
|---|---|
| Verify handler | In-process evaluation. Design target p95 under 300 ms, excluding webhook delivery and cold start of a new serverless instance. |
| Rate limit | 120 requests per minute per credential hash, configurable with `GAB_RATE_LIMIT_PER_MINUTE`. |
| Report cap | 20 reports per organization per UTC day, configurable with `GAB_REPORT_DAILY_CAP`. |
| Magic link | 900 seconds, `GAB_MAGIC_LINK_TTL_SECONDS`. |
| Session | 43200 seconds, `GAB_SESSION_TTL_SECONDS`. |
| Webhook | 3-second timeout. Failure is recorded and does not roll back the action. |
| Audit | One row for each `/v1` response, including 401 and 429. |
| Availability | Served as a Vercel function with `maxDuration` 30 seconds. No multi-region promise. |
| Revocation pull cache | Unchanged: `Cache-Control: public, max-age=300`. |

Schema changes are SQL files under `service/kata_service/migrations/`. The seed script is the operator path for a database that should contain the demo. Production startup does not insert demo rows.

## 7. Environment variables

Set secrets in the host. Do not commit values.

`public_key_from_jwk` is the shared parser. Agent registration, mandate and agreement keys, institution keys, `KATA_PUBLISHED_KEYS`, the SDK, and `KATA_PUSH_NOTIFIER_JWK` all go through it. The object may contain only `kty`, `crv`, `x`, `y`, `kid`, `alg`, `use`, and `key_ops`, and it must be Ed25519 or P-256. A private `d` is rejected. Any other member is rejected, including a WebCrypto `ext` field. If `use` is present it must be `sig`. If `key_ops` is present it must be an array whose values are only `verify`. If `alg` is present it must be `EdDSA` for Ed25519 and `ES256` for P-256.

| Variable | Required | Secret | Purpose |
|---|---|---|---|
| `DATABASE_URL` | Production | yes | Neon Postgres. Pooled URL. |
| `DATABASE_URL_UNPOOLED` | No | yes | Direct Neon URL for `CREATE TABLE`. |
| `KATA_LOG_SIGNING_SEED` | Yes for signed log heads and outbound alerts | yes | Base64 32-byte Ed25519 seed. |
| `KATA_PUSH_NOTIFIER_JWK` | Yes for inbound revocation push | no | Public JWK for revocation push. Parsed by the shared `public_key_from_jwk` rules in the note above this table. |
| `KATA_APPEND_TOKEN` | Yes for `POST /v1/log/entries` | yes | Bearer for manual log append. |
| `GAB_ADMIN_TOKEN` | Yes to create organizations | yes | Admin bearer. |
| `GAB_RATE_LIMIT_PER_MINUTE` | No | no | Default 120. |
| `GAB_VERIFY_RATE_LIMIT_PER_MINUTE` | No | no | Default 60. Extra cap on `POST /v1/verify`. |
| `GAB_INQUIRY_RATE_LIMIT_PER_MINUTE` | No | no | Default 30. Extra cap on `POST /v1/inquiries`. |
| `GAB_REPORT_RATE_LIMIT_PER_MINUTE` | No | no | Default 10. Extra cap on `POST /v1/reports`. |
| `GAB_SMTP_HOST` | No | no | SMTP host. Mail stays off until this and the user, password, and from address are set. |
| `GAB_SMTP_PORT` | No | no | Default 587. STARTTLS. Port 465 uses implicit TLS. |
| `GAB_SMTP_USER` | No | yes | SMTP username. |
| `GAB_SMTP_PASSWORD` | No | yes | SMTP password. |
| `GAB_SMTP_FROM` | No | no | From address on the sign-in message. |
| `GAB_PUBLIC_BASE_URL` | No | no | Origin used in magic links. Default `http://127.0.0.1:8765`. |
| `GAB_REPORT_DAILY_CAP` | No | no | Default 20. |
| `GAB_MAGIC_LINK_TTL_SECONDS` | No | no | Default 900. |
| `GAB_SESSION_TTL_SECONDS` | No | no | Default 43200. |
| `GAB_DEV_MAILBOX` | No | no | `1` keeps the latest magic link in memory. |
| `GAB_DEMO` | No | no | `1` seeds memory and ignores Postgres. Local only. |
| `GAB_ALLOW_DEMO_SEED` | No | no | `1` allows `POST /v1/admin/seed-demo` to write the public demo rows into the live database. Leave unset except while loading a demo. |
| `GAB_DEFENSES` | No | no | Default on. `0` turns off the link, reputation, positive cap, ring, velocity, re-registration, and dispute-hold rules together. |
| `GAB_REQUIRE_REPORT_LINK` | No | no | Default follows `GAB_DEFENSES`. `0` scores reports that have no recorded verify. |
| `GAB_LINK_QUALITY` | No | no | Default follows `GAB_DEFENSES`. Cheap or single-counterparty links weigh less. |
| `GAB_LINK_MIN_AMOUNT` | No | no | Default 5. Below this, a verify does not let the report count. |
| `GAB_LINK_FULL_AMOUNT` | No | no | Default 100. At or above this, the link weighs in full. |
| `GAB_LINK_THIN_WEIGHT` | No | no | Default 0.25. |
| `GAB_LINK_MIN_AGE_DAYS` | No | no | Default 1. |
| `GAB_LINK_MIN_COUNTERPARTIES` | No | no | Default 2. |
| `GAB_REPORTER_REPUTATION` | No | no | Default follows `GAB_DEFENSES`. |
| `GAB_REPORT_CONSISTENCY` | No | no | Default follows `GAB_DEFENSES`. Cross-report and cluster checks on negative reports. |
| `GAB_POSITIVE_CAP` | No | no | Default follows `GAB_DEFENSES`. |
| `GAB_SETTLED_CAP_SCALES` | No | no | Default follows `GAB_DEFENSES`. Raises the settled cap with external volume and counterparty diversity. |
| `GAB_OPERATOR_HISTORY` | No | no | Default on. Does not follow `GAB_DEFENSES`. |
| `GAB_OPERATOR_HISTORY_DAYS` | No | no | Default 90. |
| `GAB_RING_DETECTION` | No | no | Default follows `GAB_DEFENSES`. |
| `GAB_RING_MIN_CLUSTER` | No | no | Default 3. Smallest volume cluster that can discount settled credit. |
| `GAB_RING_INTERNAL_RATIO` | No | no | Default 0.8. Internal volume divided by internal plus external volume. |
| `GAB_VELOCITY` | No | no | Default follows `GAB_DEFENSES`. |
| `GAB_VELOCITY_ADAPTIVE` | No | no | Default follows `GAB_DEFENSES`. Segment, burst, and cash-out checks. |
| `GAB_VELOCITY_BURST_MULTIPLE` | No | no | Default 3. |
| `GAB_VELOCITY_QUIET_DAYS` | No | no | Default 7. |
| `GAB_VELOCITY_CASHOUT_AMOUNT` | No | no | Default 500. |
| `GAB_VELOCITY_DAILY_COUNT` | No | no | Default 25 allowed verifies per UTC day per agent and per operator. |
| `GAB_VELOCITY_DAILY_AMOUNT` | No | no | Default 15,000 in the action currency per UTC day. |
| `GAB_REREG_LINK` | No | no | Default follows `GAB_DEFENSES`. |
| `GAB_REREG_SIGNAL_LOOKBACK_DAYS` | No | no | Default 90. Shared device, key, payment, timing, or evidence signals. |
| `GAB_REREG_MALICIOUS_LOOKBACK_DAYS` | No | no | Default 180. Revoked, suspended, or fraud-reported agents. |
| `GAB_INHERIT_HISTORY` | No | no | Default follows `GAB_DEFENSES`. Copies negative reports from a linked agent with decay. |
| `GAB_INHERIT_HALF_LIFE_DAYS` | No | no | Default 30. Inherited negative points halve once per this many days. |
| `GAB_DISPUTE_HOLD` | No | no | Default follows `GAB_DEFENSES`. |
| `GAB_REQUIRE_PROOFING` | No | no | Default on, including when `GAB_DEFENSES=0`. `0` scores the claimed verification level without the evidence gate. |
| `GAB_SCORE_WEIGHTS` | No | no | Optional JSON override of the `gab-score-1` weights published at `GET /v1/score-model`. Invalid JSON or an out-of-range value is a configuration error. |
| `GAB_CONSORTIUM_MATCH_THRESHOLD` | No | no | Default 2. Other members who have sighted a fingerprint before a match response includes the count. |
| `GAB_STEP_UP_APPROVAL` | No | no | Default off. `1` opens a short-lived approval when verify returns STEP_UP for an individual. |
| `GAB_STEP_UP_TTL_SECONDS` | No | no | Default 300. Capped at 900. |
| `GAB_VAPID_PUBLIC_KEY` | No | no | Public key for approval notices. Push stays quiet until this and the private key are set. |
| `GAB_VAPID_PRIVATE_KEY` | No | yes | Private key for approval notices. Do not commit it. |
| `GAB_VAPID_SUBJECT` | No | no | Contact on the push claim. Default is the bureau mail address. |

Supabase is not part of this deployment. There is no `SUPABASE_URL`, anon key, or service-role key.

## 8. Known limits of this version

- Mail is SMTP when the four SMTP variables are set, and otherwise sends nothing. The development mailbox is in memory and is not shared across serverless instances.
- Step-up approval notices stay off unless `GAB_STEP_UP_APPROVAL=1`. The push sentence is fixed and does not name a merchant, an amount, or an agent. The individual portal does not show a trust score.
- A person who already has a principal id must have that email registered against it, including through `principal_email` at agent registration. A brand-new magic link creates a new principal id and will not see another principal's agents. An existing binding is not moved.
- Anti-gaming adds a transaction link, reporter reputation, a settled-credit cap, cluster ring detection, adaptive velocity denial, re-registration history, and an evidence gate on operator and institution claims. It does not convert currencies. The evidence hash is not confirmed by an outside issuer. `/simulation` publishes one synthetic stress test, labeled `SYNTHETIC TEST DATA – not real customers`: 73% of adaptive attempted fraud dollars stopped ($0.71M executed) and 78% when attackers do not know the rules ($0.68M executed).
- Score-drop alerting uses a 50-point threshold and does not page a human.
- `GET /v1/score-model` publishes the rule weights. It does not fit them from outcomes. `risk` is `1000 - score`.
- Consortium matching is an exact fingerprint compare with a count threshold. It is not a private set intersection, and it does not share reports across institutions.
- `GAB_DEMO=1` must stay off in production because it bypasses Neon.
