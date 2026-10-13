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
- After each `/v1` response the service writes an audit row: id, time, organization, key id, method, path, status, purpose code, and agent id. The row does not include the Authorization header, the raw key, or an email address.

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

- The score is an integer from 0 to 1000 for an agent. There is no score endpoint for a person.
- Cold start, with no contributing report, starts at 500 and adds identity points: unverified 0, key_bound 40, operator_verified 120, institution_attested 200, plus 80 when the operator is active and minus 40 when the operator is not. The first reason code is `COLD_START` when nothing has been reported.
- Report weights: bank_issuer and processor_psp 1.0, wallet 0.8, merchant 0.7, agent_operator 0.4. A report filed by the agent's own operator is multiplied by 0.25.
- The same `(kind, evidence_hash)` keeps the highest weight.
- Impacts, times weight, rounded: fraud −120, chargeback −80, policy −40, settled +8, loss −30.
- A resolved dispute with outcome `upheld` drops that report from the score (`DISPUTE_UPHELD`). Outcome `partial` halves the weight.
- At most four reason codes are returned, ordered by absolute points, skipping zeros.

Acceptance: the unit test keeps the bank's fraud impact over a duplicate merchant report, and an upheld dispute removes `FRAUD_INCIDENT`.

### 2.7 Alerts

- A participant with `alerts` subscribes to an agent and a webhook URL.
- `https` is required. `http` is accepted only for `localhost` and `127.0.0.1`.
- Events are revocation, a new incident, and a score drop of 50 points or more.
- The body is `{at, kata_bureau_alert: "1", alert, signature}`. `signature` is a flattened JWS with `typ` `kata-bureau-alert+jws`, signed by `KATA_LOG_SIGNING_SEED`.
- The inbound revocation-push verifier still uses `KATA_PUSH_NOTIFIER_JWK`, which is public only and cannot sign outbound alerts.
- Delivery uses a 3-second timeout. A failed delivery does not fail the revocation, report, or status change. The alert row records whether delivery succeeded.
- Demo and memory mode record the body in process instead of opening a socket.

Acceptance: revoking an agent after a localhost subscription stores a signed `kata_bureau_alert` body.

### 2.8 Individual portal

- `POST /v1/portal/magic-link` always returns `{"sent": true}`. A new email creates a new principal id. An email already bound to a principal keeps that principal.
- The token is stored as a hash. The link lifetime is 15 minutes. The session lifetime is 12 hours.
- The development mailbox (`GAB_DEV_MAILBOX=1` or `GAB_DEMO=1`) keeps the latest link in memory. `GET /v1/dev/mailbox` is 404 when that flag is off.
- Organization magic links also always return `{"sent": true}` and send only when the email was registered in advance, so the response does not reveal whether the address exists.
- The portal lists the principal's agents, authorizations, inquiries, and incident reports, and accepts revoke and dispute.

Acceptance: after the login row is bound to the registered principal, the portal lists the agent, the inquiry, and the report, and a principal revoke makes verify return `AGENT_NOT_ACTIVE`.

### 2.9 Disputes

- A principal files a dispute against a report on their agent. Status starts at `open`.
- Admin review sets `under_review` or `resolved`. A resolved dispute requires outcome `upheld`, `rejected`, or `partial`.
- `upheld` excludes the report from the score and rescores the agent.

Acceptance: an upheld policy-violation dispute leaves the score greater than or equal to the score before review.

### 2.10 Transparency log

- Registrations, revocations, and incidents append to the existing hash-chained Merkle log.
- Log bodies carry ids and hashes. They do not carry email, report summaries, or `principal_id`.

### 2.11 Web UI

- `/` is the Global Agent Bureau home. It keeps the four KATA questions, the sample sign-and-check, the live revocation list, published keys, and the tree head, and it links to the dashboard, portal, history, docs, and GitHub.
- The header mark is the single file `service/kata_service/static/gab-logo.svg`. Replacing that file replaces the mark.
- `/dashboard` signs in with an API key or an organization email and can register an agent, run an inquiry, file an incident, list alerts, manage keys, and, with the admin token, review disputes.
- `/portal` signs in with a magic link and shows agents, authorizations, inquiries, and incidents.
- `/docs` renders this document. `/docs/api` and `/docs/openapi` describe the routes.
- The license line on each page is the PolyForm Noncommercial License.

### 2.12 Demo seed

- `GAB_DEMO=1` uses the memory repository even when `DATABASE_URL` is set, turns on the development mailbox, and seeds Harbor Agents, Northwind Wallet, Techstore, agent `shopper-01`, agreement `agr_demo`, one chargeback, and a localhost subscription.
- Public demo credentials, which must not be used in production: admin `gab-demo-admin`, operator `gab_demo_operator_public`, wallet `gab_demo_wallet_public`, merchant `gab_demo_merchant_public`, portal `principal@example.com`, organization email `ops@harbor.example`.
- `python3 -m kata_service.seed` applies the SQL migration to `DATABASE_URL`. `--demo` also inserts that data. Without `DATABASE_URL` the script exits and tells the operator to use `GAB_DEMO=1` for a local demo.

## 3. Non-functional requirements

- The process is a FastAPI app. Vercel loads `app:app` from the repository-root `app.py`. Importing the module does not open Postgres. The bureau repository opens on the first `/v1` request.
- Tests run against the memory repository and do not need a network or a database.
- Postgres schema lives in `service/kata_service/migrations/001_bureau.sql` and is applied by `PostgresRepo` on first use. KATA tables remain the revocation list, log, tree head, and FX cache.
- Webhook delivery and mail sending are protocols. Tests use an in-memory sender. Production Postgres uses an HTTP sender. The mailer defaults to printing the link. A deployment can pass another mailer. No SMTP vendor is bundled.
- Decimal amounts in stored agreements round-trip through canonical JSON.

## 4. Security and privacy

- API keys and magic-link tokens and sessions are stored as SHA-256 hashes. Admin comparison uses `hmac.compare_digest`.
- Authorization failures across tenants are 404 for missing objects the caller does not own, and 403 for a missing scope or a forbidden role.
- Request bodies are JSON objects. Agent ids, emails, evidence hashes, purpose codes, and webhook URLs are checked before use.
- Audit rows, inquiry responses, and transparency-log bodies do not contain email addresses or raw credentials.
- The development mailbox returns the latest link, including the email, and is disabled unless the flag is on. Do not enable it in production.
- `GAB_DEMO=1` ignores the production database and installs public credentials. Do not set it on Vercel production.
- Outbound webhook hosts other than localhost must be `https`.

## 5. Compliance notes

- The license is the PolyForm Noncommercial License 1.0.0. Commercial use needs a separate license from Kaan Uluer. Earlier published versions were Apache-2.0.
- Purpose limitation: an inquiry without a purpose code is rejected, and the purpose is stored on the inquiry the principal can see.
- Data minimization: evidence in the log is a hash. The principal id is a pseudonym. Email exists only on the login tables.
- The score covers agents and the operator's activity. It is not a score of a person and it is not a consumer credit report.
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

| Variable | Required | Secret | Purpose |
|---|---|---|---|
| `DATABASE_URL` | Production | yes | Neon Postgres. Pooled URL. |
| `DATABASE_URL_UNPOOLED` | No | yes | Direct Neon URL for `CREATE TABLE`. |
| `KATA_LOG_SIGNING_SEED` | Yes for signed log heads and outbound alerts | yes | Base64 32-byte Ed25519 seed. |
| `KATA_PUSH_NOTIFIER_JWK` | Yes for inbound revocation push | no | Public JWK. A private `d` is rejected. |
| `KATA_APPEND_TOKEN` | Yes for `POST /v1/log/entries` | yes | Bearer for manual log append. |
| `GAB_ADMIN_TOKEN` | Yes to create organizations | yes | Admin bearer. |
| `GAB_RATE_LIMIT_PER_MINUTE` | No | no | Default 120. |
| `GAB_REPORT_DAILY_CAP` | No | no | Default 20. |
| `GAB_MAGIC_LINK_TTL_SECONDS` | No | no | Default 900. |
| `GAB_SESSION_TTL_SECONDS` | No | no | Default 43200. |
| `GAB_DEV_MAILBOX` | No | no | `1` keeps the latest magic link in memory. |
| `GAB_DEMO` | No | no | `1` seeds memory and ignores Postgres. Local only. |

Supabase is not part of this deployment. There is no `SUPABASE_URL`, anon key, or service-role key.

## 8. Known limits of this version

- Mail delivery is a plug-in. The default mailer writes the link to the process log. There is no bundled SMTP or hosted mailbox.
- The development mailbox is in memory and is not shared across serverless instances.
- A person who already has a principal id must have that email registered against it. A brand-new magic link creates a new principal id and will not see another principal's agents.
- Anti-gaming is deduplication, reporter weight, a self-report discount, and the daily cap. It is not a graph or a velocity model.
- Score-drop alerting uses a 50-point threshold and does not page a human.
- `GAB_DEMO=1` must stay off in production because it bypasses Neon.
