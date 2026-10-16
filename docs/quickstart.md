# Quickstart

Global Agent Bureau is an agent bureau and a technology company. The framework is KATA. This page is the first path through the live API: authenticate, register an agent, verify an action, inquire, file a report, and check a webhook signature.

The license is PolyForm Noncommercial.

A registered agent is not the same thing as an allowed action. Verify is the action check. An inquiry reads the record and does not change the score. Individuals are not scored.

The base URL is `https://globalagentbureau.com`. Replace `YOUR_KEY` with the API key issued for your organization. The key is shown once at issue time. These examples do not contain a real key.

## Auth

Bureau routes expect a bearer token:

```
Authorization: Bearer YOUR_KEY
```

An agent operator can register agents. A merchant, wallet, or bank can verify, inquire, and file a report. Scopes are fixed from the organization type when the key is issued.

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

`POST /v1/subscriptions` registers an `https` URL. The posted JSON has `alert`, `at`, `kata_bureau_alert` set to `"1"`, and `signature`.

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
