# GAB Migration Plan (living document)

**Engineering checklist.** This document is not a legal determination, a compliance claim, or a certification.

**RULE: Update this file whenever infra, env vars, schema (migrations), vendors/subprocessors, or domains change.**
Versioning: add a dated changelog entry at the top; before editing, copy the current file to `migration-plan.vN.md` (N = version being replaced). Never delete old versions.

## Changelog
- **v3 - 2026-10-17 (America/Halifax)**: Proof of concept stays on Vercel and Neon. No new cloud account. The master key is a Vercel Sensitive environment variable. Migration `017_subject_deks.sql` stores wrapped per-person data keys apart from ciphertext. Deleting a row shreds the live database. Those keys travel with the Neon backup. A copy of the master key belongs in a separate place such as a password manager. If the Vercel account is compromised the master key is lost too. The env provider is the proof-of-concept default and is for synthetic data. Real customer personal data requires a KMS decision and the hosting migration first. The AWS KMS class stays in the code and is not the default. Previous text is `migration-plan.v2.md`.
- **v3 - 2026-10-17 (America/Halifax)**: Phase 1 PR-1 keyed identifiers. Migration `011_keyed_identifiers.sql` adds nullable `email_hmac`, `email_kid`, `email_ciphertext` on `gab_logins` and `gab_org_logins`, and `subject_hmac` / `subject_kid` on `gab_magic_links`. Flags default off: `GAB_KEYED_IDENTIFIERS`, `GAB_HMAC_RATE_SUBJECT`, `GAB_STOP_PLAINTEXT_EMAIL`. The offline backfill is `service/scripts/backfill_keyed_identifiers.py` (dry-run default, backup confirmation, `--approve`, idempotent). It is not run by this change. `token_hash` stays plain SHA-256. Previous text is `migration-plan.v2.md`.
- **v2 - 2026-10-17 (America/Halifax)**: Phase 1 PR-0 key custody. Kaan's decisions recorded in code: breach-register retention 5 years (later PR); ledger and identifier keys are KMS-backed. No KMS account exists yet. The service now has a host-neutral key-provider interface. `aws-kms` wraps per-subject data keys with a master key that stays in AWS KMS. `env` (`GAB_HMAC_KEYS`) is explicitly non-production, for tests and this PoC, and is refused when `GAB_ENV=production` unless `GAB_ALLOW_ENV_KEYS=1`. No key material is committed. App code does not assume Vercel. Previous text is `migration-plan.v1.md`. That archived copy also omits a retired preview hostname, because a repository test rejects that hostname in `docs/`.
- **v1 - 2026-10-17 (America/Halifax)**: First version. Based on phase0-report.md, phase1-pr-plan.md and code at kaanuluer/KATA main @ 5a7aef4 (clone at /workspace/compliance/src). Read-only; no production changes, no secrets read or printed.

Status: Vercel Hobby (kata-service, function region iad1) + Neon Postgres (AWS us-east-1) are **PoC infrastructure only**. A migration is triggered only by a real company sale/contract. Decisions in force: the proof of concept stays on Vercel and Neon, with the master key in the Vercel environment and wrapped data keys in Postgres; the AWS KMS class is a future option and is not the default; real customer personal data requires a KMS decision and the hosting migration first; breach register retention 5 years; data stays in the US (until a Canada decision, ENG-31, Phase 2).

## 1. Triggers and principles
- Trigger: signed first paying/real-data customer, or any real-person data entering production. Until then this plan is a ready-to-run checklist.
- Principles: no real person data on the PoC stack; keep ledger verifiable across the move (signing key and chain unchanged); rollback available until the old stack is decommissioned; every vendor listed as subprocessor before cutover.
- Nothing is executed without Kaan's explicit approval; no merges without "birleştir".

## 2. Target options (brief comparison; no recommendation, trade-offs only)
The app is a FastAPI/ASGI Python 3.12 service (app.py, `pip install ./reference/python ./service`), stateless, with Postgres via DATABASE_URL (pooled) and DATABASE_URL_UNPOOLED (migrations). No crons, no file storage, no websockets. So it is portable to any host that runs a container or ASGI app.

| Option | Pros | Cons / trade-offs |
|---|---|---|
| A. Vercel Pro/Enterprise + Neon paid (same vendors, US) | Smallest change: zero code/DNS/passkey change; log retention 1d/3d, region pinning, SLA, commercial-use terms fixed; fastest | Still serverless cold starts; Vercel logs short; KMS must be an external cloud account; enterprise buyers may want own cloud |
| B. AWS (ECS Fargate or App Runner + RDS/Aurora Postgres, us-east-1) + AWS KMS | KMS native; PITR and backup region controlled; same region as Neon so low latency during cutover; strong compliance story, matches Gabe demo cloud | More ops (VPC, IAM, patching); higher fixed cost; own CI/CD and logging to build |
| C. Azure (Container Apps + Azure Database for PostgreSQL + Key Vault) | Fits Microsoft-centric enterprise buyers | No existing footprint; US region choice needed; ops and cost like B |
| D. GCP (Cloud Run + Cloud SQL + Cloud KMS) | Cloud Run is closest to serverless model; Cloud KMS simple | New vendor; ops like B |
| E. Fly.io/Render/Railway + managed Postgres | Cheap, simple | Weaker compliance attestations; KMS external; fewer enterprise-grade controls |
| F. Customer-hosted / dedicated tenancy | Satisfies strict buyers | Per-customer ops; it is the Gabe model, not GAB |

Decision criteria (to be weighed by Kaan/lawyer): where buyer wants data; SOC 2/ISO attestations of vendor; KMS and key custody; PITR/backup region; log retention; cost; ops load; time-to-cutover. Canada residency would change the choice (ENG-31, Phase 2) and is not decided.
**Target chosen: UNKNOWN (open item O1).**

## 3. Inventory of everything to move
### 3.1 Service code
- Repo kaanuluer/KATA: `service/` (kata_service), `reference/python` (kata_intent), `app.py`, `vercel.json`, `.github/workflows/ci.yml`. Build: `pip install ./reference/python ./service`; smoke import `kata_intent, kata_service.asgi`. Runtime python3.12, maxDuration 30s.
- vercel.json also sets security headers (CSP, X-Frame-Options, nosniff, Referrer-Policy, Permissions-Policy) for all paths: **must be reproduced at the new edge/reverse proxy** (or moved into app middleware). Easy to forget.
- Static assets served by the service (service/kata_service/static). Marketing site globalagentbureau.com may be a separate Vercel project: UNKNOWN (O5); Gabe marketing is a separate repo/project and out of scope.
- Container image / Dockerfile: does not exist yet (to create for non-Vercel targets).

### 3.2 Environment variables (names only; values never recorded here)
Secrets (sensitive, must go to the target secret store): `DATABASE_URL`, `DATABASE_URL_UNPOOLED`, `POSTGRES_*` (Neon integration set: POSTGRES_URL, POSTGRES_URL_NON_POOLING, etc.), `NEON_PROJECT_ID` (not needed after move), `KATA_LOG_SIGNING_SEED`, `KATA_APPEND_TOKEN`, `GAB_ADMIN_TOKEN`, `GAB_SMTP_PASSWORD`, `GAB_VAPID_PRIVATE_KEY`, `GAB_MASTER_KEY` (proof-of-concept wrapping key; Vercel Sensitive; also keep a copy in a password manager), `GAB_HMAC_KEYS` (env provider only; do not commit), `GAB_KMS_WRAPPED_HMAC_KEYS` (only if the future AWS option is turned on; ciphertext; still treat as sensitive).
Provider names (not the master key): `GAB_KEY_PROVIDER` (unset, or `env` for the proof of concept; `aws-kms` only when chosen later), `GAB_SYNTHETIC_DATA` (`1` on the proof of concept while `GAB_ENV` is production), `GAB_KMS_KEY_ID`, `GAB_KMS_REGION`, `GAB_HMAC_ACTIVE_KID`. `GAB_SYNTHETIC_DATA` does not make the env provider production custody. Real customer personal data requires a KMS decision and the hosting migration first.
Non-secret config: `GAB_ENV`, `GAB_PUBLIC_BASE_URL`, `GAB_SMTP_HOST/PORT/USER/FROM`, `GAB_VAPID_PUBLIC_KEY`, `GAB_VAPID_SUBJECT`, `KATA_PUSH_NOTIFIER_JWK` (public JWK), `KATA_PUBLISHED_KEYS`, `KATA_FX_SOURCE_URL`, `GAB_MAGIC_LINK_TTL_SECONDS`, `GAB_SESSION_TTL_SECONDS`, `GAB_STEP_UP_APPROVAL`, `GAB_STEP_UP_TTL_SECONDS`, `GAB_DEMO`, `GAB_ALLOW_DEMO_SEED`, `GAB_DEV_MAILBOX` (**must be off in a real production**), and the tuning set: `GAB_RATE_LIMIT_PER_MINUTE`, `GAB_INQUIRY_/GAB_VERIFY_/GAB_REPORT_RATE_LIMIT_PER_MINUTE`, `GAB_REPORT_DAILY_CAP`, `GAB_DEFENSES`, `GAB_VELOCITY*`, `GAB_LINK_*`, `GAB_REREG_*`, `GAB_RING_*`, `GAB_SETTLED_CAP_*`, `GAB_NEW_REPORTER_*`, `GAB_SCORE_WEIGHTS`, `GAB_REQUIRE_PROOFING`, `GAB_REQUIRE_REPORT_LINK`, `GAB_REPORTER_REPUTATION`, `GAB_REPORT_CONSISTENCY`, `GAB_OPERATOR_HISTORY*`, `GAB_INHERIT_*`, `GAB_POSITIVE_CAP`, `GAB_DISPUTE_HOLD`, `GAB_CONSORTIUM_MATCH_THRESHOLD`, `GAB_LINK_QUALITY`, `GAB_RING_DETECTION`, `GAB_VELOCITY_ADAPTIVE`.
Method to export: list names and non-secret values via the Vercel connector (names only in docs); secrets are re-provisioned directly into the new secret store, never through chat or files. Diff the new env name list against section 3.2 at cutover.
Note: `KATA_LOG_SIGNING_SEED` is the Ed25519 ledger signing seed. **It must move unchanged** or the published public key (KATA_PUBLISHED_KEYS) no longer verifies old entries; see section 5.

### 3.3 Postgres schema and migrations
- Migrations 001_bureau through 010_step_up (applied in production per Phase 0; `gab_schema_migrations.applied_at` holds literal "applied", so migration times are UNKNOWN). `011_keyed_identifiers.sql` and `017_subject_deks.sql` are in the tree and are additive. They have not been applied by this plan. Files: service/kata_service/migrations/. 33 tables in `public` before these files (gab_* and kata_*, listed in phase0-report.md section 3). `017` adds `gab_subject_deks`.
- Migrations are CREATE ... IF NOT EXISTS and auto-apply at first DB request per process (`bureau_pg.py _ensure()`), through the unpooled URL. **Risk:** pointing a new app at an empty DB silently creates empty schema; at cutover, restore data first, then start the app. Planned 011-014 (Phase 1) must be applied to source or target consistently: **freeze schema changes during migration window**.
- Extensions/roles/grants: UNKNOWN (O6): check `pg_extension`, roles, and whether Neon-specific features (branching, pooler/pgbouncer) are relied on. Planned append-only role/trigger for consent and breach register must be recreated on the target.

### 3.4 DB data
- Row counts, size and real-vs-synthetic split: UNKNOWN (O3; rows not read). Production is known to contain synthetic data, some of it labeled SYNTHETIC TEST DATA; cleanup of synthetic production data is a separate open item and **should be done before the move (or exclude `is_test` rows)**, subject to Kaan's approval.
- Data classes to handle specially: plaintext email (gab_logins, gab_org_logins); unsalted email_hash (to be replaced by keyed HMAC, see section 5); gab_rate raw IP; gab_push_devices endpoint and auth_secret; ledger tables kata_log_entries, kata_tree_head, kata_revocations (hash chained: copy byte-exact, no re-serialization); gab_sessions and gab_magic_links (ephemeral: do not migrate, force re-login).
- Approach: logical dump (pg_dump custom format, schema + data) over TLS in the US only, restore to target, verify counts/checksums (section 8). Large-data alternative: logical replication (needs Neon logical replication enabled; plan dependent, UNKNOWN) for near-zero downtime.

### 3.5 DNS, domains, mail
- Domains: globalagentbureau.com and globalagentbureau.org (+www), plus the PoC host's vercel.app aliases (these vanish with that host; any hardcoded use must be found: grep found only globalagentbureau.com in security.txt, logo URL, VAPID default subject mailto:info@globalagentbureau.com).
- Registrar and DNS host: UNKNOWN (O4). TTL, existing records (A/CNAME, MX, SPF, DKIM, DMARC, CAA, TXT verification records) must be exported before change.
- Mail: inbound info@globalagentbureau.com (security.txt contact) forwarding provider/destination UNKNOWN (O4). Outbound: SMTP via GAB_SMTP_HOST (provider and location UNKNOWN, O2). Moving hosting does not require changing SMTP, but SPF/DKIM must still authorize the sender; if the provider changes, update SPF/DKIM/DMARC and warm up, and add to subprocessor list.
- TLS: certificates are issued by Vercel today; the new target issues its own (ACME/managed). Keep CAA records compatible with both during overlap.

### 3.6 Cron / routines
- Current: none (vercel.json has no crons; no purge jobs exist). Planned Phase 1 PR-6: `/internal/retention` guarded by admin token, nightly. On the new host schedule via native scheduler (EventBridge/Cloud Scheduler/etc.) with run log kept as evidence. Hobby cron limit (once/day) is UNKNOWN-verified and disappears after the move.
- Also external: GitHub Actions CI (ci.yml) unaffected; cursor/agent routines are not part of runtime. Quarterly evidence export (ENG-28) to be scheduled on the new host.

### 3.7 Passkey RP ID / origin (HIGH IMPACT)
- `passkeys.py relying_party(origin)`: **the RP ID is the hostname of the request origin** (e.g. globalagentbureau.com); expected_origin = that origin. Credentials in gab_passkeys are bound to the RP ID they were created under.
- Consequence: if production keeps serving the portal on `globalagentbureau.com`, passkeys keep working after the move (same RP ID), provided DNS is cut over and TLS valid. If any users registered under `*.vercel.app` hostnames, or if the hostname changes (e.g. .com to .org or a subdomain), those passkeys **will not work** and users need re-registration via magic link. Check which hosts passkeys were registered under: gab_webauthn_challenges.rp_id/origin hold this (transient) and rp id is not stored per credential: UNKNOWN (O7). Mitigation: pin the portal to one canonical host and set an allow-list; do not change the RP host during migration.
- Also: the app derives origin from the request, so the new proxy must pass the original Host/X-Forwarded-Host/proto correctly; wrong forwarding breaks WebAuthn and magic links.

### 3.8 Push keys
- Web Push uses VAPID: GAB_VAPID_PRIVATE_KEY, GAB_VAPID_PUBLIC_KEY, GAB_VAPID_SUBJECT. **The VAPID key pair must move unchanged**: browser push subscriptions (gab_push_devices.endpoint, p256dh, auth_secret) are bound to the applicationServerKey; a new key invalidates all subscriptions and every user must re-subscribe (re-consent flow). KATA_PUSH_NOTIFIER_JWK is the public notifier JWK (check it matches).
- Endpoints are browser-vendor URLs (no own push provider), so no provider move. auth_secret is plaintext today; Phase 1 envelope-encrypts it: do the re-encryption before or after the move, not during.

### 3.9 Magic-link domains
- Links are built from `GAB_PUBLIC_BASE_URL` (default http://127.0.0.1:8765). Must be set to the canonical production host on the new stack. Links issued before cutover point at the old host: either keep old host redirecting/serving during the TTL (GAB_MAGIC_LINK_TTL_SECONDS default 900s; session TTL GAB_SESSION_TTL_SECONDS) or accept that in-flight links expire. Magic-link tokens are single use and stored hashed in gab_magic_links; they need not be migrated.
- Email templates reference https://globalagentbureau.com/assets/gab-logo.png (bureau.py): the asset path must stay reachable (marketing site vs service: UNKNOWN, O5).

### 3.10 Other
- Webhooks: gab_subscriptions.webhook_url values are customer endpoints; outbound IP changes after the move (allow-listing on customer side). Notify design partners. Egress IP of the old/new stack: UNKNOWN.
- Org API keys stay valid (hash only in DB, no re-issue needed). Do not log them in transit.
- KATA_FX_SOURCE_URL egress must be allowed on the new host.
- Monitoring/alerting, log drains, status page: none verified (UNKNOWN, O8). Must exist on target before go-live.

## 4. Compliance checkpoints (must be green before cutover)
| # | Checkpoint | Requirement | Status |
|---|---|---|---|
| C1 | Region | App and DB in US region(s) chosen by Kaan; no cross-region replicas or backups outside the US; no Canada-residency claim | Source: iad1 + us-east-1. Target UNKNOWN |
| C2 | Backups / PITR | Defined PITR window, backup region documented (in US), restore test done on target | Source UNKNOWN (Neon plan/PITR unknown) |
| C3 | Key custody | Proof of concept: master key in the Vercel Sensitive environment, copy in a password manager, wrapped per-person data keys in `gab_subject_deks` (they travel with the Neon backup). Deleting a row shreds the live database only. Accepted risk: a compromised Vercel account exposes the master key. AWS KMS remains a future option and is not the default. Real customer personal data requires a KMS decision and the hosting migration first. | The env provider is the proof-of-concept default. `aws-kms` is implemented and not selected unless named. No new cloud account. |
| C4 | Log retention | Runtime/access logs retained per policy (source: 1 hour on Hobby), no PI in logs (raw IP in gab_rate, URL query tokens), log drain to US storage, retention documented | Target UNKNOWN |
| C5 | Subprocessors | Updated list incl. host, DB, KMS, SMTP, DNS/registrar, mail forwarder, monitoring, browser push services (user-chosen); DPAs signed; lawyer review | Source list not compiled (UNKNOWN) |
| C6 | Retention | Breach register 5 years (decision); retention jobs (PR-6) deployed on target; legal hold support | Planned |
| C7 | Data minimization | Synthetic/test rows removed or excluded; plaintext email handling per PR-1; sessions/magic links not migrated | Open |
| C8 | Encryption | TLS 1.2+ in transit; encryption at rest on DB and backups | Target UNKNOWN |
| C9 | Access | Least-privilege DB roles, no shared admin credentials, production access logged, MFA on cloud/registrar/DNS accounts | Open |
| C10 | Commercial terms | Hobby plan commercial-use restriction no longer applies on target | Needs lawyer check |
| C11 | Notification | Customers/design partners informed of subprocessor change and egress IP change as contracts require | Open |

## 5. Data and key migration steps (crypto / KMS)
Order matters: keys first, then data, then app. The proof of concept does not run this section. It keeps `GAB_MASTER_KEY` in Vercel and wrapped data keys in Neon. The steps below are for a later move, after a KMS decision.
1. **Create the KMS** in the chosen US region (key policy, separate admin and use roles, audit logging on). The code can speak to AWS KMS through `AwsKmsEnvelopeProvider` when `GAB_KEY_PROVIDER=aws-kms`. That provider is not the proof-of-concept default. Another cloud can implement the same `KmsClient` methods; the target cloud is still UNKNOWN (O1), so naming AWS here is not a hosting decision. No KMS account exists yet. Create: (a) ledger signing key, (b) HMAC key ring (email/IP keyed HMAC, with `kid`, wrapped by the master key), (c) the master KEK used for per-subject DEKs, (d) a separate wrap for push `auth_secret` if that key is not the same master key. Do not use `GAB_HMAC_KEYS` or `GAB_MASTER_KEY` on that future target.
2. **Ledger signing key.** Today an Ed25519 seed in env `KATA_LOG_SIGNING_SEED` signs ledger entries; published public key(s) in `KATA_PUBLISHED_KEYS`. Two options, trade-offs:
   - (i) Move the existing seed into KMS-managed secret storage (wrapped, fetched at startup): old and new entries verify with the same published key; the seed does exist in plaintext in the app memory.
   - (ii) Rotate to a KMS-native non-exportable signing key (note: AWS KMS/GCP support ECDSA/RSA, and Ed25519 support varies by provider/version: UNKNOWN, O9; if Ed25519 is unsupported, rotation changes algorithm). Rotation requires publishing a new key id, keeping the old public key verifiable for historical entries, and a signed key-rotation entry in the ledger bridging old to new key. Do not reuse chain heads without that entry.
   Either way: back up the existing seed offline (sealed, two-person) before the move; verify the full chain on the target before cutover.
3. **Email identifiers.** The lookup key, once `GAB_KEYED_IDENTIFIERS` is on, is `HMAC-SHA256` with a kid (`v1:<kid>:<hex>`). The offline script `service/scripts/backfill_keyed_identifiers.py` fills `email_hmac` and `email_ciphertext` from plaintext email. It is shipped unexecuted: dry-run does not connect; a write needs a verified backup id, a verified backup time, the phrase `BACKUP-VERIFIED`, and `--approve`. If the hosting move happens before that script has run, copy `email_hash` and plaintext email, then run the script on the target. Do not carry the unsalted hash as the final state. HMAC keys must be the same on source and target during any overlap where both write. `GAB_STOP_PLAINTEXT_EMAIL` stays off until that backfill has been checked.
4. **Envelope encryption / crypto-shredding (PR-4).** Per-subject DEKs wrapped by the KEK; DEK store outside the Postgres backup path. During migration copy wrapped DEKs and ciphertext together and test unwrapping in the target KMS **before** cutover; if the KMS provider changes, re-wrap DEKs (unwrap with old KEK, wrap with new KEK) in a controlled batch job; never export plaintext DEKs to disk.
5. **Data copy.** Freeze schema; take a consistent logical dump from Neon unpooled endpoint (read-only transaction); restore to target Postgres in the US; run migrations check (all 11+ versions present); verify row counts, per-table checksums, and ledger chain head hash equals source.
6. **Backup of source** retained (encrypted) until the rollback window closes; then destroyed with a destruction log entry. Legal hold overrides.
7. Secrets: re-provision directly in the target secret store; rotate after cutover: `GAB_ADMIN_TOKEN`, `KATA_APPEND_TOKEN`, SMTP password, DB credentials. Rotating `GAB_VAPID_*` is **not** done (see 3.8). Old Neon/Vercel credentials revoked at decommission.

## 6. Cutover plan
Pre-cutover (T-14 to T-1 days):
1. Choose target (O1), create accounts with MFA, region US, KMS, logging, backups; build image/IaC; stage env.
2. Deploy the app on the target against a restored copy of data (or empty schema plus synthetic data); run test suite and ledger verification; run smoke on target preview hostname (not the production host: passkeys will not work there, so test passkeys only on a staging host with its own RP ID).
3. Lower DNS TTL to 60-300s at T-3 days (record the old TTL).
4. Announce window to design partners; confirm egress IPs.
5. Restore drill: restore a backup into a scratch DB and time it. Record RTO/RPO.
Cutover (maintenance window, low-traffic, e.g. weekend morning America/Halifax):
1. T0: put source into read-only/maintenance mode (return 503 with Retry-After for writes; reads of verify may continue if DB is read only). Stop schema changes.
2. Take final dump from Neon; restore to target; verify counts, checksums, ledger head hash.
3. Start the target app with production env; confirm migrations are a no-op; run smoke: /health, verify (hosted ALLOW), magic-link email, passkey login on production host name (via hosts-file override before DNS flip if possible), push test, ledger append + verify, admin routes.
4. Flip DNS (A/CNAME for apex and www, .com and .org). Keep MX/TXT untouched. Watch propagation.
5. Monitor errors/latency for 60 minutes; compare hot/cold verify latency to the PoC baseline (measurement still open).
6. Declare success; leave the old stack read-only (not deleted) for the rollback window (suggest 7-14 days, to be confirmed).
Downtime plan: expected write downtime = dump/restore time + DNS propagation; for a small DB (size UNKNOWN) estimate minutes to under 1 hour. Zero-downtime alternative with logical replication is possible if size or customer SLA requires it (needs plan support). Real downtime figure to be set after the restore drill. Users in flight: sessions are not migrated (re-login), magic links expire in 15 minutes by default, passkeys survive if the host name is unchanged, push subscriptions survive if VAPID unchanged.

## 7. Rollback plan
- Rollback window: until old stack decommission (default 7-14 days).
- Before DNS flip (steps 1-3): abort, remove maintenance mode on source; no data divergence.
- After DNS flip, early (target has no/few writes): revert DNS to source (TTL low), remove maintenance mode; export any rows written on target since T0 and replay into source if any (writes should be few; track the max created_at at T0).
- After meaningful writes on target: do NOT flip back blindly. Choose forward-fix, or dump target delta (rows after T0 by created_at/at columns; ledger entries appended on target must be appended in order to the source chain to keep it valid) and replay. Ledger is hash-chained: never run two writers on the chain at once; enforce a single writer through the maintenance flag.
- Keys: the old stack's secrets stay valid until the window closes; the KMS-created keys stay. If the signing key was rotated, rollback must still accept the bridge entry; keep both public keys published.
- Decision owner and rollback criteria (error rate threshold, failed login rate, ledger verify failure, data mismatch) written before T0.

## 8. Verification checklist (go/no-go)
Before cutover: [ ] target region = US and documented; [ ] KMS key policies reviewed; [ ] restore drill timed; [ ] env name diff against section 3.2 clean (names only); [ ] GAB_DEV_MAILBOX/GAB_DEMO off in production; [ ] security headers (CSP etc.) present on responses; [ ] TLS valid for apex, www, .com, .org; [ ] SPF/DKIM/DMARC pass on a test mail to a mailbox we own; [ ] subprocessor list updated.
After restore: [ ] all migration versions present; [ ] table list equals 33 (+ new); [ ] per-table row counts and checksums match; [ ] ledger: full chain verifies, head hash equals source, signature verifies with published key; [ ] no unsalted hash left after PR-1 backfill (if applicable).
After cutover: [ ] /health 200; [ ] org API key verify (synthetic org) works; [ ] hosted ALLOW decision works; [ ] individual magic-link login works from new host; [ ] passkey login works for an existing synthetic account (RP host unchanged); [ ] push subscription and test push; [ ] step-up approval flow; [ ] ledger append and verify; [ ] rate limit works behind new proxy (client IP header trusted correctly, not the proxy IP; asgi.py:182 uses client IP when no bearer); [ ] logs show no PI/secrets; [ ] latency hot/cold measured; [ ] backups running and PITR works; [ ] alerts fire on a test failure.
Evidence: store outputs in /workspace/compliance/migration-evidence/ (no secrets), named by date.

## 9. Owners (proposed; confirm with Kaan)
| Area | Owner |
|---|---|
| Go/no-go, target choice, vendor contracts, DNS/registrar accounts | Kaan |
| Legal (subprocessors, DPAs, Hobby terms, residency) | Lawyer |
| Architecture, runbook, verification, raw results | CTO |
| Implementation (image/IaC, migrations, scripts), executing approved steps | Devolopi (via Cursor cloud agents; production steps only with Kaan's approval) |
| KMS custody, key ceremony, sealed backup of signing seed | Kaan (+ second person: UNKNOWN) |
| Customer notices | Kaan |

## 10. Open items / UNKNOWN
- O1 Target hosting/cloud and region: UNKNOWN (Kaan; see options in section 2).
- O2 SMTP provider/location and its subprocessor status: UNKNOWN.
- O3 DB size, row counts, real vs synthetic data split; Neon plan, PITR window, backup location: UNKNOWN.
- O4 Registrar, DNS host, existing DNS records/TTL, mail forwarding provider for info@ and other aliases: UNKNOWN.
- O5 Whether marketing site (globalagentbureau.com) is a separate Vercel project and who serves /assets: UNKNOWN.
- O6 Postgres extensions, roles, grants, reliance on Neon pooler/branching: UNKNOWN.
- O7 Which hostnames existing passkeys were registered under (RP ID); canonical host policy: UNKNOWN.
- O8 Monitoring, alerting, log drains: UNKNOWN.
- O9 Ed25519 support in the chosen KMS (affects ledger signing key option ii): UNKNOWN until target chosen.
- O10 Maximum acceptable downtime/SLA expectation of the first customer: UNKNOWN.
- O11 Second key custodian for the sealed seed backup: UNKNOWN.
- O12 Customer contractual residency/notification requirements (and Canada decision ENG-31): UNKNOWN.
- O13 Phase 1 PRs (011-014) timing relative to migration: not decided; recommended to complete PR-0/PR-1 first so the move does not carry unsalted hashes (decision for Kaan). PR-0 is the key-provider interface only; it does not migrate rows.
- O15 KMS account: not created, and not required for the proof of concept. The proof of concept uses the env master key. AWS KMS stays in the code as a future option. Real customer personal data requires that decision and the hosting migration first.
- O14 Egress IPs for webhooks/customer allow-lists: UNKNOWN.
