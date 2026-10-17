# Key rotation

The Global Agent Bureau service reads its secrets from the host environment. The current proof-of-concept host is the Vercel project `kata-service`. This note says how to rotate them. It does not contain values. A move off that host is described in [migration-plan.md](migration-plan.md). Key custody is in [key-custody.md](key-custody.md).

GAB is an agent bureau. KATA is the framework.

## Production rules

- `GAB_ALLOW_DEMO_SEED` stays off on production. Leave it unset, or set it to `0`. The service treats only `1`, `true`, and `yes` as on.
- `GAB_ADMIN_TOKEN` is the bearer for organization administration. It must not be the public demo string used by the local demo. Generate a new value locally and paste it into Vercel. Do not put it in a pull request, an issue, a log, or this file.
- `GAB_DEMO` stays unset on Vercel. That switch is for a local in-memory demo.

## What to rotate

| Variable | Where it is used |
|---|---|
| `GAB_ADMIN_TOKEN` | Bearer for admin routes, including organization creation |
| `KATA_LOG_SIGNING_SEED` | Signs the transparency log and bureau alert webhooks |
| `KATA_APPEND_TOKEN` | Authorizes appends to the log |
| `KATA_PUSH_NOTIFIER_JWK` | Public key that verifies revocation push. Rotating it means publishing the new public key and keeping the private key off the server |
| `GAB_HMAC_KEYS` | Non-production env provider only. A new kid changes new HMAC outputs. Keep the old kid until stored identifiers are re-keyed. Do not commit the JSON. |
| `GAB_KMS_KEY_ID` | AWS KMS master key that wraps data keys. Rotate inside KMS and re-wrap data keys. Do not export the master key. |
| `GAB_KMS_WRAPPED_HMAC_KEYS` | HMAC data keys already wrapped by the master key. Add a new wrapped kid and keep the old one until lookups are re-keyed. |

`DATABASE_URL` and `DATABASE_URL_UNPOOLED` come from the database host. On the proof of concept that host is Neon. Rotate credentials at the database, then update the host environment. Do not paste a database URL into a pull request.

The steps below are the proof-of-concept procedure on Vercel. Another host uses its own secret store and its own restart. Do not put `GAB_HMAC_KEYS` on a production target; that provider is for tests and the PoC. Production HMAC and envelope keys use `GAB_KEY_PROVIDER=aws-kms`.

## Steps

1. Generate the new value on a machine you control. The commands for the log seed and the notifier key are in [service/README.md](../service/README.md).
2. In Vercel, open `kata-service` → Settings → Environment Variables. Update the production value, and the preview value when that target uses the same secret.
3. Redeploy production so the running service picks up the new value. A saved variable does not change the deployment that is already live.
4. Confirm the site still answers `GET /v1/score-model` and that an admin call with the old bearer fails.
5. Discard the old value. Do not archive it in git.

Rotating `KATA_LOG_SIGNING_SEED` changes the log public key. Clients that pin the old key need the new key from `GET /.well-known/kata-keys.json` after the redeploy.

## Pull requests

Do not paste demo keys or live secrets into pull request descriptions. Name the variable. Say whether production is unchanged. Leave the value in the host secret store.
