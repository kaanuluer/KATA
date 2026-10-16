# Quickstart

Global Agent Bureau is an agent bureau and a technology company. The framework is KATA. This page is the first path through the live API: authenticate, register an agent, verify an action, inquire, file a report, check a webhook signature, use the MCP endpoint, and issue a test key.

The license is PolyForm Noncommercial.

A registered agent is not the same thing as an allowed action. Verify is the action check. An inquiry reads the record and does not change the score. Individuals are not scored.

The base URL is `https://globalagentbureau.com`. Replace `YOUR_KEY` with the API key issued for your organization. The key is shown once at issue time. These examples do not contain a real key.

## Auth

Bureau routes expect a bearer token:

```
Authorization: Bearer YOUR_KEY
```

Scopes are fixed from the organization type when the key is issued. An agent operator can register agents, verify, file a report, and subscribe. That organization does not receive the `inquire` scope, so `POST /v1/inquiries` is refused for its key. A merchant, wallet, or bank can inquire.

## Register an agent

`POST /v1/agents` is for an agent operator. `verification_level` may be `unverified`, `key_bound`, or `operator_verified`.

```bash
curl -sS -X POST https://globalagentbureau.com/v1/agents \
  -H "Authorization: Bearer YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{"agent_id":"shopper-01","principal_id":"prn_example","verification_level":"operator_verified","public_key":{"kty":"OKP","crv":"Ed25519","x":"REPLACE_WITH_PUBLIC_KEY"}}'
```

## Verify

`POST /v1/verify` checks one action against a stored agreement. The verdict is `ALLOW`, `DENY`, or `STEP_UP`. Deny blocks the action. It does not revoke the grant.

```bash
curl -sS -X POST https://globalagentbureau.com/v1/verify \
  -H "Authorization: Bearer YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{"agent_id":"shopper-01","action":{"action_id":"act_1","action_type":"purchase","amount":1300,"currency":"CAD","item":"Laptop","context":{"merchant":"techstore.example"},"parameters":{"merchant":"techstore.example","quantity":1},"proposed_at":"2026-10-16T12:00:00Z"}}'
```

## Inquire

`POST /v1/inquiries` takes a purpose code: `payment_authorization`, `account_opening`, `fraud_investigation`, `dispute_resolution`, `ongoing_monitoring`, or `agent_onboarding`.

```bash
curl -sS -X POST https://globalagentbureau.com/v1/inquiries \
  -H "Authorization: Bearer YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{"agent_id":"shopper-01","purpose_code":"payment_authorization"}'
```

## Report

`POST /v1/reports` files `transaction_outcome`, `fraud_incident`, `chargeback`, or `policy_violation`. `evidence_hash` is `sha256:` plus 64 hex characters. The report is accepted when this organization has an allowed verify with that agent.

```bash
curl -sS -X POST https://globalagentbureau.com/v1/reports \
  -H "Authorization: Bearer YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{"agent_id":"shopper-01","kind":"chargeback","evidence_hash":"sha256:abababababababababababababababababababababababababababababababab","summary":"Disputed purchase.","action_id":"act_1"}'
```

## Webhook signatures

`POST /v1/subscriptions` registers an `https` URL. `http` is rejected, including `http://localhost`, and so is an `https` URL whose host is a loopback name. The posted JSON has `alert`, `at`, `kata_bureau_alert` set to `"1"`, and `signature`.

`signature` is a flattened JWS. The protected header `typ` is `kata-bureau-alert+jws`. The signed bytes are the same object without the `signature` field.

Fetch the log public key from `GET /.well-known/kata-keys.json`. Use the key whose `kid` matches the JWS header. Reject the message when verification fails.

```bash
curl -sS -X POST https://globalagentbureau.com/v1/subscriptions \
  -H "Authorization: Bearer YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{"agent_id":"shopper-01","webhook_url":"https://merchant.example/hooks/gab"}'
```

```bash
curl -sS https://globalagentbureau.com/.well-known/kata-keys.json
```

`POST /v1/webhooks/test` sends one signed test alert to a subscription this organization already owns. The subscription and the delivery stay in the environment of the key.

```bash
curl -sS -X POST https://globalagentbureau.com/v1/webhooks/test \
  -H "Authorization: Bearer YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{"subscription_id":"sub_example"}'
```

## Sandbox

Live keys use the `gab_` prefix. Test keys use the `gab_test_` prefix. Ask for a test key with `"environment": "test"` when the key is issued. The secret is shown once. A later list shows the prefix and `environment`, not the secret.

`GAB_ENV` is `production` or `sandbox`. Production is the default and accepts both kinds of key. A sandbox deployment accepts only `gab_test_` keys. A live key on that deployment receives 403.

The same agent id can exist once in each environment. Agreements, inquiries, reports, subscriptions, deliveries, and scores stay with the key that wrote them. A test key does not read a live row, and a test report does not change a live score. `POST /v1/webhooks/test` fires only at a subscription in that same environment.

## MCP

`POST /mcp` is the remote MCP endpoint, protocol revision `2026-07-28`. Send `Authorization: Bearer` and an API key. `GET` on `/mcp` is not the protocol. The longer note is `/docs/mcp`.

Five tools:

| Tool | Scope |
| --- | --- |
| `verify_agent` | `verify` |
| `inquire` | `inquire` |
| `report` | `report` |
| `check_revocation` | any API key |
| `fetch_signed_receipt` | any API key |

`tools/list` returns only the tools the key's scopes allow. An agent operator organization does not receive `inquire`, so that tool is absent from its list. `tools/call` runs one tool. A `gab_test_` key uses the test partition. On `GAB_ENV=sandbox`, a live key is refused.

```bash
curl -sS -X POST https://globalagentbureau.com/mcp \
  -H "Authorization: Bearer YOUR_KEY" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "MCP-Protocol-Version: 2026-07-28" \
  -H "Mcp-Method: tools/call" \
  -H "Mcp-Name: verify_agent" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"verify_agent","arguments":{"agent_id":"shopper-01","action":{"action_id":"act_1","action_type":"purchase","amount":1300,"currency":"CAD","proposed_at":"2026-10-16T12:00:00Z"}},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}'
```

## Health

`GET /health` and `GET /v1/health` do not take an API key. HTTP 200 and `"status": "ok"` means the process is answering. `database` is `ok` when the configured database answered, `memory` when this process is using the in-memory store, and `unavailable` when the check failed. A failed check is HTTP 503. The body does not include the database address.

The same reading is on `/status`.

```bash
curl -sS https://globalagentbureau.com/health
curl -sS https://globalagentbureau.com/v1/health
```

## Limits

Each `/v1` request counts toward `GAB_RATE_LIMIT_PER_MINUTE` (default 120). `POST /v1/verify` also counts toward `GAB_VERIFY_RATE_LIMIT_PER_MINUTE` (default 60). `POST /v1/inquiries` counts toward `GAB_INQUIRY_RATE_LIMIT_PER_MINUTE` (default 30). `POST /v1/reports` counts toward `GAB_REPORT_RATE_LIMIT_PER_MINUTE` (default 10).

`POST /mcp` counts toward the same per-minute cap. `verify_agent`, `inquire`, and `report` also count toward the matching route caps.

Over a per-minute limit, the HTTP API and `POST /mcp` return 429 with the message `rate limit exceeded`. The response includes `Retry-After: 60`.

## Python

`sdk/python/gab.py` is a small client. Put that directory on `PYTHONPATH`. Webhook checks use the KATA reference library in this repository.

```python
from gab import Client, verify_alert

client = Client("YOUR_KEY")
client.inquire("shopper-01", "payment_authorization")
# message is the JSON posted to your webhook URL.
# public_jwk is one object from /.well-known/kata-keys.json, under public_key.
verified = verify_alert(message, public_jwk)
```
