# Key custody

Engineering note for identifier HMAC and envelope encryption. This is not a legal determination, a compliance claim, or a certification.

The service does not assume a particular app host. The proof of concept runs on Vercel and Neon. A later move is tracked in [migration-plan.md](migration-plan.md).

## Model

Production custody is a KMS master key that never leaves KMS. That key wraps per-subject data keys and wraps the HMAC data keys used for identifiers. AWS KMS is the first implementation (`GAB_KEY_PROVIDER=aws-kms`). The calls are `GenerateDataKey`, `Encrypt`, and `Decrypt` with an encryption context. Another KMS can implement the same three methods later. No KMS account exists yet.

`GAB_KEY_PROVIDER=env` is **non-production**. Key bytes live in `GAB_HMAC_KEYS` in the process environment. It is for unit tests and for the proof of concept until a KMS account exists. When `GAB_ENV=production`, the service refuses this provider unless `GAB_ALLOW_ENV_KEYS=1`. That flag is an explicit acknowledgement. It does not make the keys production custody.

Unset `GAB_KEY_PROVIDER` leaves current behavior unchanged.

## HMAC

Outputs look like `v1:<kid>:<64 hex chars>`. The message is `gab-hmac-v1`, a NUL, the purpose (`identifier`, `rate`, `subject`, or `network`), a NUL, and the value. `kek` is a wrapping purpose, not an HMAC purpose.

Keep old kids until stored identifiers are re-keyed. Lookups try every kid configured for the purpose. The active kid is the one new writes use. Set it with `"active": true` on a ring entry, or with `GAB_HMAC_ACTIVE_KID` (one id, or a JSON object of purpose to id).

`token_hash` stays plain SHA-256. Those inputs are high-entropy random secrets, not personal identifiers.

## Envelope

`seal` draws a 32-byte data key, wraps it with the master key (KMS) or the local `kek` purpose (env provider), and encrypts the plaintext with AES-256-GCM. The subject id is bound into the additional data. Opening with a different subject id fails.

The encoded blob embeds the wrapped data key so a caller can store one string. That is convenient for a column. It is not crypto-shredding against a database backup: a restore brings back the wrapped key and the ciphertext together. A later change stores wrapped data keys outside the database backup path and destroys that copy to shred payloads. Destroying the KMS master key is a separate, account-level action and is not what per-subject shredding does.

## AWS HMAC wrap context

Wrap each HMAC data key with `Encrypt` under the master key and this encryption context. Store only the ciphertext blob, base64, in `GAB_KMS_WRAPPED_HMAC_KEYS`. Do not commit the plaintext or the ciphertext.

```text
{"gab": "hmac-key", "purpose": "<purpose>", "kid": "<kid>"}
```

Per-subject data keys use:

```text
{"gab": "subject-dek", "purpose": "subject-dek", "subject_id": "<subject id>"}
```

## What not to commit

Do not commit `GAB_HMAC_KEYS`, wrapped blobs, data keys, the master key, or database URLs. Tests build key bytes from the label `SYNTHETIC TEST DATA` in memory.

## Preview

A preview deploy with `GAB_KEY_PROVIDER` unset does not call KMS and does not change request handling. Setting `aws-kms` without a reachable key, or `env` without the allow flag on a production-labeled environment, sets a configuration error. `/v1` routes then return 500 until the configuration is fixed. This pull request does not apply a database migration.
