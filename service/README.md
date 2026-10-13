# KATA deployment service

**Status: Concept / Open Design — not production ready.**

This is the Vercel host for the pieces the reference library keeps behind interfaces: the revocation pull list, the signed push webhook, the transparency log, `/.well-known/kata-keys.json`, and a daily FX feed. The cryptographic objects are the ones in [`reference/python`](../reference/python). This process does not render a wallet and it does not evaluate purchases.

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
| `GET` | `/v1/revocations` | none | Pull list. `Cache-Control: public, max-age=300`. Body is `{"revocations": [...]}`. |
| `POST` | `/v1/revocations/push` | notifier JWS | Stores a principal revocation and appends it to the log. A second delivery of the same revocation does not append again. |
| `POST` | `/v1/log/entries` | `Authorization: Bearer $KATA_APPEND_TOKEN` | Append `{ "kind": "agreement" or "revocation", "body": { ... } }` and sign a new tree head. |
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
