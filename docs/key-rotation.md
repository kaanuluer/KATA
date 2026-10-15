# Key rotation

The Global Agent Bureau service reads its secrets from the Vercel project `kata-service`. This note says how to rotate them. It does not contain values.

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

`DATABASE_URL` and `DATABASE_URL_UNPOOLED` come from the Neon integration. Rotate those in Neon, then reconnect the integration. Do not paste a database URL into a pull request.

## Steps

1. Generate the new value on a machine you control. The commands for the log seed and the notifier key are in [service/README.md](../service/README.md).
2. In Vercel, open `kata-service` → Settings → Environment Variables. Update the production value, and the preview value when that target uses the same secret.
3. Redeploy production so the running service picks up the new value. A saved variable does not change the deployment that is already live.
4. Confirm the site still answers `GET /v1/score-model` and that an admin call with the old bearer fails.
5. Discard the old value. Do not archive it in git.

Rotating `KATA_LOG_SIGNING_SEED` changes the log public key. Clients that pin the old key need the new key from `GET /.well-known/kata-keys.json` after the redeploy.

## Pull requests

Do not paste demo keys or live secrets into pull request descriptions. Name the variable. Say whether production is unchanged. Leave the value in Vercel.
