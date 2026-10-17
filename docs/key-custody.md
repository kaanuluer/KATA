# Key custody

Engineering note for identifier HMAC and envelope encryption. This is not a legal determination or a compliance claim.

The proof of concept stays on Vercel and Neon. No new cloud account is required for this note. A later move is tracked in [migration-plan.md](migration-plan.md).

## H1. Authentication and the master key

The proof of concept does not use AWS credentials. `GAB_MASTER_KEY` is a 32-byte key, base64, stored as a Vercel Sensitive environment variable. The process uses it only to wrap and unwrap per-person data keys. HMAC keys, when keyed identifiers are turned on, stay in `GAB_HMAC_KEYS`.

Leaving `GAB_KEY_PROVIDER` unset and leaving `GAB_MASTER_KEY` unset does not change request handling. Setting `GAB_MASTER_KEY` selects the `env` provider. That is the proof-of-concept default. `GAB_KEY_PROVIDER=aws-kms` is used only when that name is set. It is not the default.

When `GAB_ENV=production`, the env provider also requires `GAB_SYNTHETIC_DATA=1`. That flag confirms the rows are synthetic. Real customer personal data is out of scope for this provider. Storing it requires revisiting KMS and the hosting migration first.

The AWS client is created on the first KMS call, not when the process starts. The proof of concept does not import boto3 at startup. The class `AwsKmsEnvelopeProvider` remains so a later KMS can use the same wrap and unwrap calls. Turning it on needs `GAB_KMS_KEY_ID` and `GAB_KMS_REGION`. No AWS account is created for the proof of concept.

Accepted risk: if the Vercel account is compromised the master key is lost too. An attacker who also reads the database can unwrap the data keys.

## Envelope

`seal` draws a 32-byte data key, wraps it with `GAB_MASTER_KEY` (or the local `kek` purpose in tests), and encrypts with AES-256-GCM. The subject id is not stored. Callers pass the raw id. The encryption context, the additional data, and `gab_subject_deks.subject_ref` store `opaque_subject`, a SHA-256 of a fixed label and the id.

`seal` can embed the wrapped data key in one string. That form is not shredding: deleting the ciphertext deletes the wrapped key with it, and a backup restores both. The shred path is `seal_detached`: the ciphertext string does not contain the wrapped key. `DatabaseDekStore` writes the wrapped key to `gab_subject_deks`. `shred_subject` deletes that row and drops the process cache.

Unwrapped data keys are cached in the process, keyed by the opaque subject and a hash of the wrapped blob. A second unwrap of the same blob is a cache hit and does not repeat the wrap operation. Each HMAC, issue, unwrap, seal, and unseal appends a usage event with the operation, purpose, key id, opaque subject, cache hit or miss, and latency in milliseconds. The event does not include plaintext, key bytes, or the raw subject id.

## H3. Backup, restore, and shredding

Keep a copy of `GAB_MASTER_KEY` in a separate place Kaan controls, such as a password manager. The master key is not in the database. Losing both the Vercel variable and that copy makes every wrapped data key unreadable.

Wrapped per-person data keys live in `gab_subject_deks` and travel with the Neon backup. Restoring the database restores those keys. Deleting a row shreds the live database. A backup taken before the delete still contains the wrapped key, and restoring that backup brings the key back.

Ledger payload ciphertext is a separate table, `gab_payloads`. Its wrapped data key is the `gab_subject_deks` row, not a file beside the database.

## AWS HMAC wrap context

This block is the future option, not the proof-of-concept path. Wrap each HMAC data key with `Encrypt` under the KMS master key and this encryption context. Store only the ciphertext blob, base64, in `GAB_KMS_WRAPPED_HMAC_KEYS`.

```text
{"gab": "hmac-key", "purpose": "<purpose>", "kid": "<kid>"}
```

Per-subject data keys use an opaque `subject_ref`, not the raw id:

```text
{"gab": "subject-dek", "purpose": "subject-dek", "subject_ref": "<sha256 hex>"}
```

## HMAC

Outputs look like `v1:<kid>:<64 hex chars>`. The message is `gab-hmac-v1`, a NUL, the purpose (`identifier`, `rate`, `subject`, or `network`), a NUL, and the value. `kek` is a wrapping purpose, not an HMAC purpose.

Keep old kids until stored identifiers are re-keyed. Lookups try every kid configured for the purpose. The active kid is the one new writes use. Set it with `"active": true` on a ring entry, or with `GAB_HMAC_ACTIVE_KID` (one id, or a JSON object of purpose to id).

`token_hash` stays plain SHA-256. Those inputs are high-entropy random secrets, not personal identifiers.

## Identifiers and rate subjects

`GAB_KEYED_IDENTIFIERS` defaults off. When it is on, new login rows store `v1:<kid>:<hex>` in `email_hmac` and an envelope in `email_ciphertext`. Reads try every configured identifier kid, then the legacy unsalted `email_hash`. Plaintext `email` is still written until `GAB_STOP_PLAINTEXT_EMAIL=1`. Leave that second flag off until the offline backfill has run. The backfill is `service/scripts/backfill_keyed_identifiers.py`. It is not started by the service. Dry-run is the default and does not open a database. A write needs `--execute`, `--approve`, a verified backup id, a verified backup time, and the phrase `BACKUP-VERIFIED`.

`GAB_HMAC_RATE_SUBJECT` defaults off. When it is on, a request with no bearer stores an HMAC of the client host (purpose `rate`) instead of the raw host, and rate rows older than 24 hours are deleted. Bearer subjects stay `token_hash` (plain SHA-256 of a high-entropy secret). Rows younger than 24 hours can still hold a raw host until they age out.

## What not to commit

Do not commit `GAB_MASTER_KEY`, `GAB_HMAC_KEYS`, wrapped blobs, data keys, or database URLs. Tests build key bytes from the label `SYNTHETIC TEST DATA` in memory.

## Preview

A preview with `GAB_KEY_PROVIDER` and `GAB_MASTER_KEY` unset does not select a provider and does not write data keys. This change adds `017_subject_deks.sql`. The service applies additive `CREATE TABLE IF NOT EXISTS` on the first database request. A preview that shares the production database URL creates that empty table there. Leave the master key unset on that preview. Do not put key material in the repository.
