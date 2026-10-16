# Global Agent Bureau service

This is the Vercel host for Global Agent Bureau and for the KATA deployment pieces the reference library keeps behind interfaces: the revocation pull list, the signed push webhook, the transparency log, `/.well-known/kata-keys.json`, and a daily FX feed. The cryptographic objects are the ones in [`reference/python`](../reference/python).

The bureau API registers organizations and agents, stores signed intents, verifies payments, records incidents, answers purpose-coded inquiries, and computes the rule-based trust score. Requirements are in [`docs/gab-requirements.md`](../docs/gab-requirements.md).

One Postgres database is used. Neon is already connected on Vercel. Supabase is not used, and no Supabase environment variables are required.

## Vercel project

Create the project from this Git repository. Use these settings. Do not deploy from a filled `.env` file in the repo.

| Setting | Value |
|---|---|
| Root Directory | `.` (the repository root, not `service/`) |
| Framework Preset | FastAPI |
| Install Command | `pip install ./reference/python ./service` |
| Build Command | `python -c "import kata_intent, kata_service.asgi"` |
| Output Directory | empty |
| Python | 3.12 |

The root has to be the repository root because the install command installs both the reference library and this service. [`vercel.json`](../vercel.json) sets the FastAPI framework, the install command, the build command, and a 30-second function limit. [`pyproject.toml`](../pyproject.toml) points Vercel at `app:app`. The root [`app.py`](../app.py) imports that object from `kata_service.asgi`. Secret values are not written there. Set the names below in the Vercel project.

Leave the Output Directory empty. This is a Function, not a static build.

## Storage

Install **Neon Postgres** from the Vercel Marketplace (the Vercel-managed integration) and connect it to this project for Production, Preview, and Development.

- Do not set an environment-variable prefix. The service reads `DATABASE_URL`.
- Neon also injects `DATABASE_URL_UNPOOLED`. Schema creation uses that direct URL when it is present.
- `POSTGRES_URL` is accepted when `DATABASE_URL` is unset, for the legacy variable name.

The first request creates the tables `kata_revocations`, `kata_log_entries`, `kata_tree_head`, and `kata_fx_rates`. Tests use an in-memory store and do not need Neon.

## Environment variables

Set these on the Vercel project. Generate the secret values on your machine and paste them into Vercel. The repo ships names only, in [`.env.example`](.env.example).

| Variable | Required | Secret | Purpose |
|---|---|---|---|
| `DATABASE_URL` | yes | yes | Pooled Neon URL. The Marketplace sets this when the integration is connected. |
| `DATABASE_URL_UNPOOLED` | no | yes | Direct Neon URL for `CREATE TABLE`. The Marketplace sets this too. |
| `KATA_LOG_SIGNING_SEED` | yes | yes | Base64 of a 32-byte Ed25519 seed. Signs transparency-log tree heads. |
| `KATA_PUSH_NOTIFIER_JWK` | yes | no | Public JWK JSON of the key that signs revocation push webhooks. A private `d` parameter is rejected. |
| `KATA_APPEND_TOKEN` | yes | yes | Bearer token for `POST /v1/log/entries`. |
| `KATA_PUBLISHED_KEYS` | no | no | JSON array of extra `.well-known` key records. Each record has a public `public_key`. |
| `KATA_FX_SOURCE_URL` | no | no | Daily rate origin. Default `https://api.frankfurter.dev/v1` (ECB rates, no API key). |
| `GAB_ADMIN_TOKEN` | yes, to create organizations | yes | Bearer token for the admin bootstrap and dispute review. |
| `GAB_RATE_LIMIT_PER_MINUTE` | no | no | Default 120 `/v1` calls per minute per credential hash. |
| `GAB_VERIFY_RATE_LIMIT_PER_MINUTE` | no | no | Default 60. Extra cap on `POST /v1/verify`. |
| `GAB_INQUIRY_RATE_LIMIT_PER_MINUTE` | no | no | Default 30. Extra cap on `POST /v1/inquiries`. |
| `GAB_REPORT_RATE_LIMIT_PER_MINUTE` | no | no | Default 10. Extra cap on `POST /v1/reports`. |
| `GAB_SMTP_HOST` | no | no | SMTP host. Leave unset to keep mail off. |
| `GAB_SMTP_PORT` | no | no | Default 587. |
| `GAB_SMTP_USER` | no | yes | SMTP username. |
| `GAB_SMTP_PASSWORD` | no | yes | SMTP password. |
| `GAB_SMTP_FROM` | no | no | From address on the sign-in message. |
| `GAB_PUBLIC_BASE_URL` | no | no | Origin written into magic links. |
| `GAB_REPORT_DAILY_CAP` | no | no | Default 20 reports per organization per UTC day. |
| `GAB_MAGIC_LINK_TTL_SECONDS` | no | no | Default 900. |
| `GAB_SESSION_TTL_SECONDS` | no | no | Default 43200. |
| `GAB_DEV_MAILBOX` | no | no | `1` keeps the latest magic link in memory at `GET /v1/dev/mailbox`. Leave unset in production. |
| `GAB_DEMO` | no | no | `1` seeds a memory bureau and ignores `DATABASE_URL`. Local demos only. |
| `GAB_ALLOW_DEMO_SEED` | no | no | `1` allows `POST /v1/admin/seed-demo`. The bearer is `GAB_ADMIN_TOKEN`. The call writes the public demo into the live database and can be repeated. |
| `GAB_DEFENSES` | no | no | Default on. `0` turns off transaction links, reporter reputation, the settled-credit cap, ring detection, velocity step-up, re-registration penalties, inherited history, and the dispute hold. Individual flags override that default. |
| `GAB_INHERIT_HISTORY` | no | no | Default on with `GAB_DEFENSES`. A linked re-registration copies negative reports, halving every `GAB_INHERIT_HALF_LIFE_DAYS` (30). |
| `GAB_REREG_SIGNAL_LOOKBACK_DAYS` | no | no | Default 90. |
| `GAB_REREG_MALICIOUS_LOOKBACK_DAYS` | no | no | Default 180. |
| `GAB_VELOCITY_DAILY_COUNT` | no | no | Default 25 allowed verifies per UTC day. |
| `GAB_VELOCITY_DAILY_AMOUNT` | no | no | Default 15000 in the action currency per UTC day. |
| `GAB_REQUIRE_PROOFING` | no | no | Default on, including when `GAB_DEFENSES=0`. `0` scores the claimed verification level. `POST /v1/agents/{id}/proofing` files an operator review or an institution attestation hash. |
| `GAB_SCORE_WEIGHTS` | no | no | Optional JSON override of the weights at `GET /v1/score-model`. Invalid JSON or an out-of-range value makes `/v1` return 500. |
| `GAB_CONSORTIUM_MATCH_THRESHOLD` | no | no | Default 2 other members. Below that, `POST /v1/consortium/match` returns `matched: false` and omits the count. |

Generate a log seed, a push notifier, and an append token:

```bash
cd reference/python
PYTHONPATH=src python3 -c '
import base64, json, secrets
from kata_intent import generate_keypair
log_key = generate_keypair("EdDSA")
notifier = generate_keypair("EdDSA")
print("KATA_LOG_SIGNING_SEED=" + base64.b64encode(log_key.seed).decode())
print("KATA_PUSH_NOTIFIER_JWK=" + json.dumps(notifier.public.to_jwk()))
print("KATA_APPEND_TOKEN=" + secrets.token_urlsafe(32))
'
```

Put the three lines into Vercel environment variables. The notifier JWK is public. The seed and the append token are secret. The public half of the log key is published at `/.well-known/kata-keys.json` so verifiers can check tree heads. The seed itself is not published.

## Routes

| Method | Path | Auth | Behavior |
|---|---|---|---|
| `GET` | `/` | none | Global Agent Bureau home. Four KATA questions, sample intent check, revocation list, published keys, tree head, and the repository timeline. |
| `GET` | `/dashboard` | browser session or API key | Organization dashboard. |
| `GET` | `/portal` | browser session | Individual portal. |
| `GET` | `/history` | none | The same timeline: commit dates, `CHANGELOG.md`, and GitHub pull requests. |
| `GET` | `/docs` | none | Documentation index: design, authorization, intent, threat model, related docs, schemas, and the API reference. |
| `GET` | `/docs/design` | none | `docs/intent-agreement.md`, including the lifecycle section. |
| `GET` | `/docs/authorization` | none | `docs/delegation-model.md`. |
| `GET` | `/docs/intent` | none | `docs/intent-model.md`. |
| `GET` | `/docs/threat-model` | none | `docs/threat-model.md`. |
| `GET` | `/docs/schemas` | none | Index of `schemas/*.json`. |
| `GET` | `/docs/schemas/{name}.json` | none | One schema file, unchanged, as `application/json`. |
| `GET` | `/docs/api` | none | Endpoint reference with request and response examples. |
| `GET` | `/docs/openapi` | none | FastAPI's generated OpenAPI page. `/openapi.json` is the document. |
| `POST` | `/demo/check` | none | Signs a sample intent with the public demo keys and returns `ALLOW`, `DENY`, or `STEP_UP`. |
| `GET` | `/v1/revocations` | none | Pull list. `Cache-Control: public, max-age=300`. Body is `{"revocations": [...]}`. |
| `POST` | `/v1/revocations/push` | notifier JWS | Stores a principal revocation and appends it to the log. A second delivery of the same revocation does not append again. |
| `POST` | `/v1/log/entries` | `Authorization: Bearer $KATA_APPEND_TOKEN` | Append `{ "kind": "agreement", "revocation", "registration", or "incident", "body": { ... } }` and sign a new tree head. |
| `GET` | `/v1/log/entries/{sequence}` | none | One hash-chained entry. |
| `GET` | `/v1/log/entries/{sequence}/proof` | none | Merkle inclusion proof (`leaf`, `index`, `proof`, `root`, `tree_size`). |
| `GET` | `/v1/log/head` | none | Signed tree head (`typ` `kata-tree-head+jws`). |
| `GET` | `/.well-known/kata-keys.json` | none | Log public key, plus `KATA_PUBLISHED_KEYS`. |
| `GET` | `/v1/fx?currency=CAD&reference=USD&day=2026-10-04` | none | Reference-currency units for one unit of `currency` on that UTC day. `reference_currency` is an alias of `reference`. The same currency returns `1`. |

A verifier's pull fetcher should return the `revocations` array. The rate string is the value `DailyTableRates` stores for `(currency, reference, day)`.

The FX fetcher is `FrankfurterFx`. Pass another object with `fetch(currency, day, reference_currency)` into `create_app` to replace it. Results are cached in the store.

## Local tests

```bash
cd service
python3 -m pip install -e ../reference/python -e '.[dev]'
python3 -m pytest
```

The handler tests use the memory store. They do not call Frankfurter and they do not need `DATABASE_URL`.

## Bureau demo

Local demo, in memory, with public credentials:

```bash
cd service
GAB_DEMO=1 python3 -m uvicorn kata_service.asgi:app --host 127.0.0.1 --port 8765
```

Open `/dashboard` and `/portal`. The public demo keys are `gab_demo_operator_public`, `gab_demo_wallet_public`, `gab_demo_merchant_public`, and admin `gab-demo-admin`. The portal email is `principal@example.com`. With `GAB_DEMO=1` the development mailbox is on, so the page can exchange the latest magic link. Do not set `GAB_DEMO` on a production deployment.

To create the tables on Neon and, optionally, insert the same demo rows:

```bash
cd service
python3 -m kata_service.seed
python3 -m kata_service.seed --demo
```

`seed` reads `DATABASE_URL`. It does not print secret values. Bureau routes under `/v1` are listed on `/docs/api` and `/docs/openapi`. Outbound alert webhooks are signed with `KATA_LOG_SIGNING_SEED` (`typ` `kata-bureau-alert+jws`) because `KATA_PUSH_NOTIFIER_JWK` is a public key.

On a deployed service that can see Neon, set `GAB_ALLOW_DEMO_SEED=1` and call `POST /v1/admin/seed-demo` with `Authorization: Bearer $GAB_ADMIN_TOKEN`. Leave `GAB_DEMO` unset so the write goes to Postgres. The route is idempotent. Unset `GAB_ALLOW_DEMO_SEED` after the demo rows are in place. The migration file is packaged with the service (`migrations/*.sql`), so the first `/v1` request can create the tables from the installed copy.
