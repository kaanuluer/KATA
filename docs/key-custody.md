# Key custody

Engineering note for identifier HMAC and envelope encryption. This is not a legal determination or a compliance claim.

The proof of concept stays on Vercel and Neon. No new cloud account is required for this note. A later move is tracked in [migration-plan.md](migration-plan.md).

## H1. Authentication and the master key

The proof of concept does not use AWS credentials. `GAB_MASTER_KEY` is a 32-byte key, base64, stored as a Vercel Sensitive environment variable. The process uses it only to wrap and unwrap per-person data keys. HMAC keys, when keyed identifiers are turned on, stay in `GAB_HMAC_KEYS`.

Leaving `GAB_KEY_PROVIDER` unset and leaving `GAB_MASTER_KEY` unset does not change request handling. Setting `GAB_MASTER_KEY` selects the `env` provider when `GAB_ENV` is not `production`. That is the proof-of-concept default. `GAB_KEY_PROVIDER=aws-kms` is used only when that name is set. It is not the default.

`GAB_KEY_PROVIDER=env` is refused when `GAB_ENV` is `production`. `GAB_SYNTHETIC_DATA` and `GAB_ALLOW_ENV_KEYS` do not override this. A proof-of-concept process that needs the env provider sets `GAB_ENV=sandbox`. Real customer personal data requires a KMS decision and the hosting migration first.

`GAB_ENV` defaults to `production` when it is unset. Setting `GAB_MASTER_KEY` or `GAB_KEY_PROVIDER=env` on that default does not select the env provider. Settings load with `config_error` and `key_provider` empty, so envelope encryption and keyed HMAC stay off. This note does not change that default.

## Accepted decision

On 2026-10-17 Kaan approved this: the proof-of-concept key-custody feature runs only in a separate sandbox project. That project sets `GAB_ENV=sandbox`. The feature is not enabled in production. Until a real customer arrives, the only data is synthetic.

The `GAB_ENV` default stays `production`. The production refusal stays. `GAB_SYNTHETIC_DATA` and `GAB_ALLOW_ENV_KEYS` do not override it.

Consequence: setting `GAB_MASTER_KEY` or `GAB_KEY_PROVIDER=env` on the live Vercel production project yields `config_error` and an empty `key_provider`. Envelope encryption and keyed HMAC stay off there.

Whether `config_error` stops the whole service is UNKNOWN.

This decision is reopened when the first real customer arrives, together with the KMS decision and the hosting migration.

`017_subject_deks.sql` creates `gab_subject_deks` in `public`. This feature does not use the `gab_sandbox` schema. Migration `006` creates `gab_sandbox` and copies other bureau tables into it. It does not create `gab_subject_deks`. Do not set the master key on the production project.

Accepted risk: if the Vercel account is compromised the master key is lost too. An attacker who also reads the database can unwrap the data keys.

### Future AWS path: Vercel OIDC, not long-lived keys

`boto3`'s default credential chain will use `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` when those variables exist. That is a long-lived key on Vercel, and it is not the design. `Boto3KmsClient` refuses those variables, and it also refuses `AWS_SESSION_TOKEN` set in the environment. The client is created on the first KMS call. The process does not import boto3 at startup, and it does not check that the key is reachable at startup. The first `GenerateDataKey`, `Encrypt`, or `Decrypt` is the first network call.

The future path is Vercel OIDC federation into one IAM role. No AWS account is created for the proof of concept. The examples below use placeholders. They are not a real account, role, or key.

Install the client with the optional extra `pip install 'kata-service[aws]'` (`boto3`). The default install does not include it.

Vercel publishes two issuer modes. Team issuer mode is the one this note uses. Confirm the issuer and claims against the current Vercel OIDC reference when the role is created.

- Issuer: `https://oidc.vercel.com/TEAM_SLUG`
- Audience: `https://vercel.com/TEAM_SLUG`
- Subject: `owner:TEAM_SLUG:project:PROJECT_NAME:environment:production`

Trust policy. The runtime role can be assumed only by that project in production:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::ACCOUNT_ID:oidc-provider/oidc.vercel.com/TEAM_SLUG"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "oidc.vercel.com/TEAM_SLUG:aud": "https://vercel.com/TEAM_SLUG",
          "oidc.vercel.com/TEAM_SLUG:sub": "owner:TEAM_SLUG:project:PROJECT_NAME:environment:production"
        }
      }
    }
  ]
}
```

Permission policy. The role may only wrap and unwrap data keys on one key ARN, and only with the encryption contexts this service sends. It cannot schedule deletion, disable the key, or change the key policy, because those actions are not in the allow list.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "WrapSubjectDataKeys",
      "Effect": "Allow",
      "Action": ["kms:GenerateDataKey", "kms:Decrypt", "kms:Encrypt"],
      "Resource": "arn:aws:kms:REGION:ACCOUNT_ID:key/KEY_ID",
      "Condition": {
        "StringEquals": {
          "kms:EncryptionContext:gab": "subject-dek",
          "kms:EncryptionContext:purpose": "subject-dek"
        }
      }
    },
    {
      "Sid": "WrapHmacKeys",
      "Effect": "Allow",
      "Action": ["kms:GenerateDataKey", "kms:Decrypt", "kms:Encrypt"],
      "Resource": "arn:aws:kms:REGION:ACCOUNT_ID:key/KEY_ID",
      "Condition": {
        "StringEquals": {
          "kms:EncryptionContext:gab": "hmac-key"
        }
      }
    }
  ]
}
```

On the host, set `AWS_ROLE_ARN` to that role and `AWS_WEB_IDENTITY_TOKEN_FILE` to a file that contains the Vercel OIDC token. If `VERCEL_OIDC_TOKEN` is present and the file variable is unset, the first KMS call writes the token to a mode-`0600` file and points `AWS_WEB_IDENTITY_TOKEN_FILE` at it. Do not set `AWS_ACCESS_KEY_ID` or `AWS_SECRET_ACCESS_KEY`.

The global issuer `https://oidc.vercel.com` is a different IAM provider. IAM requires an `aud` condition on that shared issuer. This note does not use it. Preview deployments are not in the trust policy above. Add a preview subject only when a preview should call KMS.

## Envelope

`seal` draws a 32-byte data key, wraps it with `GAB_MASTER_KEY` (or the local `kek` purpose in tests), and encrypts with AES-256-GCM. The wrap uses HKDF-SHA256, not the raw secret. The salt is `gab-hkdf-v1`. The wrap info is `gab-wrap-v1`. The HMAC info is `gab-hmac-v1`, a NUL, and the purpose. Those two derived keys are different even when the input secret is the same.

The subject id is not stored. Callers pass the raw id. The encryption context, the additional data, and `gab_subject_deks.subject_ref` store `opaque_subject`. That value is HMAC-SHA256 of a fixed label and the id. The HMAC key is HKDF-SHA256 of a subject-reference secret, info `gab-subject-ref-v1`. It is not the wrapping key and not an unkeyed SHA-256, so a person who sees the reference cannot test candidate emails or names without that secret, and rotating the wrapping key does not change the digest.

On the env path the subject-reference secret is `GAB_SUBJECT_REF_KEY`, or a ring entry with purpose `ref`. Its id is `GAB_SUBJECT_REF_KID` (default `subject-ref`). On the AWS path it is `GAB_SUBJECT_REF_KEY` only. The env provider does not key `subject_ref` with the active kek. A value that is set but is not a usable subject-reference key is not written to `config_error`. The process logs `GAB_SUBJECT_REF_KEY is not a usable subject ref key` and does not log the value. Push returns 503 with that sentence. Log append and `GET /.well-known/kata-keys.json` stay up. On this service the subject-reference key is not read by any other HTTP route.

`GAB_MASTER_KEY_ID` is the id stored inside each wrapped data key. When it is unset the id is `master`. Replacing the bytes behind an existing id makes those wraps unopenable. Rotation is a new id, the new secret in `GAB_MASTER_KEY`, and the previous secret kept in `GAB_HMAC_KEYS` under purpose `kek` with the old id. Unwrap reads the id from the blob and looks that id up.

Rotating the subject-reference key changes the digest used for new writes. Keep each previous secret in the ring with purpose `ref` and not active, and pass those secrets to the store as `previous_keys` (the provider's `previous_subject_keys()`). `get` and `destroy` try the older digests, so shred still deletes the old row, and unwrap tries each digest as additional data. Dropping an old subject-reference secret without that lookup leaves the row in place, and shred will not find it. On `aws-kms` there is one `GAB_SUBJECT_REF_KEY`. Changing it without rewriting `subject_ref` is that same migration: the old rows stay under the old digest until the old secret is still available for lookup or the rows are moved.

`seal` can embed the wrapped data key in one string. That form is not shredding: deleting the ciphertext deletes the wrapped key with it, and a backup restores both. The shred path is `seal_detached` plus the store. The first call inserts the wrapped key. A second call for the same person reuses it, so the first ciphertext stays readable. `DatabaseDekStore.put` inserts with `ON CONFLICT DO NOTHING` and reads the row back, including when two callers insert together. It does not replace an existing key. `shred_subject` is the only delete. It removes the row and clears this process's cache.

`seal_detached` returns the ciphertext and the wrapped data key. If the caller stores that wrapped value, shred does not make the ciphertext unreadable. `open_detached` unwraps the bytes it is given and does not read the table. Shred deletes the store row and this process's cache only. The supported open path is `open_stored`, which reads the wrapped key from the store. After shred that read fails and the ciphertext does not open.

Unwrapped data keys are cached in the process, keyed by the opaque subject and a hash of the wrapped blob. A cache entry lives for 300 seconds, and the cache holds at most 256 entries. A second unwrap of the same blob inside that window is a cache hit and does not repeat the wrap operation. Shredding clears this process's cache immediately. Another process that already unwrapped the key keeps its copy until that cache entry expires. Each HMAC, issue, unwrap, seal, and unseal appends a usage event with the operation, purpose, key id, opaque subject, cache hit or miss, and latency in milliseconds. The event does not include plaintext, key bytes, or the raw subject id. A KMS failure raises a fixed message. The AWS error text is not copied into that message, the repr, or a log line from this module.

## H3. Backup, restore, and shredding

Keep a copy of `GAB_MASTER_KEY` in a separate place Kaan controls, such as a password manager. The master key is not in the database. Losing both the Vercel variable and that copy makes every wrapped data key unreadable.

Keep the same kind of copy of `GAB_HMAC_KEYS`. Those secrets are what recompute identifier hashes. If the Vercel copy is the only copy, a lost environment variable means stored hashes cannot be verified.

Wrapped per-person data keys live in `gab_subject_deks` and travel with the Neon backup. Restoring the database restores those keys. Deleting a row shreds the live database. A backup taken before the delete still contains the wrapped key, and restoring that backup brings the key back.

`seal` still embeds the wrapped data key in one string for callers that need a single value. That form cannot be shredded: deleting the ciphertext deletes the wrapped key with it, and a backup restores both. The shred path is `seal_detached` plus `gab_subject_deks`. A later change can move embedded callers onto that path. This note does not block that change. The detached format and the table are already in place.

### Wrapped HMAC blobs

`GAB_KMS_WRAPPED_HMAC_KEYS` is ciphertext wrapped by the KMS master key. It is not the master key, but it is the only copy of the HMAC key material the process can unwrap. If that variable is lost, identifier hashes cannot be verified even when the KMS key still exists.

Until a database table exists, keep a second copy of that ciphertext in the same password manager as the master key. The planned table stores ciphertext only, apart from any personal data, so a Neon backup carries the blobs and a row can be restored without putting plaintext HMAC keys in the database. This change does not create that table.

### KMS key lifetime, when the future option is turned on

Turn on a deletion window before the key is used. AWS allows 7 to 30 days. Use 30 days. The runtime role above cannot call `ScheduleKeyDeletion`, `DisableKey`, or `PutKeyPolicy`. A separate admin role, not the Vercel role, holds those actions. CloudTrail on the key records `GenerateDataKey`, `Encrypt`, and `Decrypt`. The encryption context carries `subject_ref`, which is the opaque digest, so the trail does not receive the raw subject id.

A multi-region key, or a second backup key in another US region, is not decided. The proof of concept does not create a KMS key. A single-region key in the same region as Neon is the smaller option. A multi-region key survives a regional KMS outage and needs a second region that stays in the US. Record the choice before any key is created.

### Generate the master key

Run this on a machine you control. Do not paste the output into a ticket, a log, or the repository.

```text
python -c "import os,base64; print(base64.b64encode(os.urandom(32)).decode())"
```

Store the line in the password manager and in the Vercel Sensitive variable `GAB_MASTER_KEY`. Generate a second line the same way and store it as `GAB_SUBJECT_REF_KEY`. Set `GAB_MASTER_KEY_ID` to a new id when the wrapping secret changes, and keep the previous secret under its old id. For the proof of concept set `GAB_ENV=sandbox` and leave `GAB_KEY_PROVIDER` unset. The unset default of `GAB_ENV` is `production`, and the env provider is then refused. Keep a second copy of `GAB_HMAC_KEYS` in the same password manager when keyed identifiers are turned on.

### Restore drill

Use a synthetic fixture or a restored copy. Do not point the drill at the production database.

1. Restore a Neon backup into a new database that is not production. The Neon plan and PITR window are still unknown, so use the backup Neon actually has.
2. Put the password-manager copy of `GAB_MASTER_KEY` into that process and set `GAB_ENV=sandbox`.
3. Read one `gab_subject_deks` row and the matching detached ciphertext from the restored copy.
4. Open the ciphertext with the restored wrapped key. The plaintext should match the known fixture.
5. On a synthetic row only, shred the subject, confirm the live row is gone and this process's cache no longer opens from memory, then restore the backup again and confirm the row is back. Another process can still hold the data key until its 300-second cache entry expires. This drill has not been performed.

## AWS HMAC wrap context

This block is the future option, not the proof-of-concept path. Wrap each HMAC data key with `Encrypt` under the KMS master key and this encryption context. Store only the ciphertext blob, base64, in `GAB_KMS_WRAPPED_HMAC_KEYS`.

```text
{"gab": "hmac-key", "purpose": "<purpose>", "kid": "<kid>"}
```

Per-subject data keys use a keyed `subject_ref`, not the raw id and not an unkeyed hash:

```text
{"gab": "subject-dek", "purpose": "subject-dek", "subject_ref": "<hmac-sha256 hex>"}
```

## HMAC

Outputs look like `v1:<kid>:<64 hex chars>`. The message is `gab-hmac-v1`, a NUL, the purpose (`identifier`, `rate`, `subject`, or `network`), a NUL, and the value. The HMAC key is HKDF-SHA256 of the ring secret, salt `gab-hkdf-v1`, info `gab-hmac-v1`, a NUL, and the purpose. `kek` and `ref` are not HMAC purposes.

Keep old kids until stored identifiers are re-keyed. Lookups try every kid configured for the purpose. The active kid is the one new writes use. Set it with `"active": true` on a ring entry, or with `GAB_HMAC_ACTIVE_KID` (one id, or a JSON object of purpose to id).

`token_hash` stays plain SHA-256. Those inputs are high-entropy random secrets, not personal identifiers.

## What not to commit

Do not commit `GAB_MASTER_KEY`, `GAB_HMAC_KEYS`, wrapped blobs, data keys, or database URLs. Tests build key bytes from the label `SYNTHETIC TEST DATA` in memory.

## Preview

A preview with `GAB_KEY_PROVIDER` and `GAB_MASTER_KEY` unset does not select a provider and does not write data keys. This change adds `017_subject_deks.sql`. The service applies additive `CREATE TABLE IF NOT EXISTS` on the first database request. A preview that shares the production database URL creates that empty table there. Leave the master key unset on that preview. Do not put key material in the repository.

Migrations `001` through `010` are already applied in production, including both files numbered `006`. This change does not renumber them. `011` through `016` are absent here because later drafts reserve them: `011` keyed identifiers, `012` consent events, `013` breach register, `014` retention (not written yet), `015` entity kind, `016` ledger payloads. `017_subject_deks.sql` has not been applied. It stays `017` so it does not collide with those files.

## Open items

Acceptable for this proof of concept. This list is not a merge approval.

- H3: the restore drill above has not been performed.
- M1
- M4
- M5
- L1
- L2
- N4: migrations `011` through `016` are reserved by later drafts, `014` is not written, `017` is not renumbered, and `001` through `010` are not renumbered.
- Drafts #46 through #50 must not merge before the rebase in this note.
- Whether `config_error` stops the whole service is UNKNOWN.

## Rebase plan for stacked drafts

Plan only. Do not rebase and do not push `#46` through `#50` until Kaan asks. Nothing here merges.

Rebase onto the tip of `cursor/key-custody-cdba` after this section is on that branch. The parent of this section is `1fc0d3c`. Do not rebase onto `0ea7846`. That commit still lets `GAB_SYNTHETIC_DATA` and `GAB_ALLOW_ENV_KEYS` select the env provider in production.

The stack was built by merging `0ea7846` into each feature branch. Those merge commits (`c8ccd78`, `fc5976d`, `8f2f60f`, `01f732f`) only pull that old key-custody commit. Do not replay them. Cherry-pick the feature commit onto the updated parent, in this order:

1. `#46` `cursor/keyed-identifiers-cdba`, commit `a7cab0b`, onto the final `#45` tip. Then point `#46`'s base at `cursor/key-custody-cdba`.
2. `#47` `cursor/consent-events-cdba`, commit `12b9e1e`, onto the updated `#46`.
3. `#48` `cursor/entity-only-cdba`, commit `0083ba3`, onto the updated `#47`.
4. `#49` `cursor/ledger-hygiene-cdba`, commit `96cb171`, onto the updated `#48`. Also bring forward the integration that exists only in merge `01f732f`: wrapped payload keys in `gab_subject_deks`, and the `DATABASE_URL` check. Do not bring forward `GAB_ALLOW_ENV_KEYS`.
5. `#50` `cursor/breach-register-cdba`, commit `2c50136`, onto the updated `#49`.

Expected conflicts:

- `docs/migration-plan.md` and a new `docs/migration-plan.vN.md` on every feature commit. `#46` archives `v2`, `#47` archives `v3`, `#48` archives `v4`, `#49` archives `v5`, `#50` archives `v6`. Those numbers now collide with the key-custody archives already on `#45` (`v3` and `v4`, and `v5` once this note is archived). Keep the archives that are already on the parent. Append the feature changelog as the next free version. Do not replace an existing archive with the feature branch's copy.
- `docs/key-custody.md`, `service/README.md`, and `service/.env.example` on `#46`. The feature text still says `GAB_SYNTHETIC_DATA=1` allows the env provider in production. Keep the parent text. Add only the keyed-identifier sentences.
- `service/tests/test_package_data.py` on each step. Keep every migration filename. The sorted list grows by `011`, then `012`, then `015`, then `016`, then `013`, and already includes `017`.
- `service/kata_service/keys.py` on `#49` only. Start from the `#45` file. Re-apply ledger behavior onto it: `seal_detached` now requires the store, `put` does not replace a key, `InProcessDekStore` and `DatabaseDekStore` take the 32-byte subject-reference secret (not the kek), and `opaque_subject` is a keyed HMAC of that secret. Pass `previous_keys` when older subject-reference secrets must still shred. `asgi.py` on that branch constructs `DatabaseDekStore` with only a connection and `InProcessDekStore` with no arguments. Pass the subject-reference key. `get` hashes its argument. `test_ledger_hygiene.py` calls `dek_store.get` with the ledger body's `subject_ref` (`v1:...`) and then passes that same string to `open_detached` as `subject_id`. Hashing it again will miss the row. Pass the raw principal id, or read the stored reference without hashing twice. A caller who keeps the wrapped bytes returned by `seal_detached` can still open after shred.
- `service/kata_service/settings.py` should take the feature flag fields. It should not restore a production bypass.

Tests to adapt. `test_keys.py` on the stacked tips is the old file from `0ea7846`. Leave `#45`'s `test_keys.py` in place. Do not put back tests that expect `GAB_SYNTHETIC_DATA=1` to load the env provider in production.

- `service/tests/test_keyed_identifiers.py` sets `GAB_KEY_PROVIDER=env` and `GAB_ALLOW_ENV_KEYS=1` and does not set `GAB_ENV`. The default is production, so the provider is refused and the rate-limit HMAC assertion fails. Set `GAB_ENV=sandbox` and remove `GAB_ALLOW_ENV_KEYS`.
- `service/tests/test_ledger_hygiene.py` sets the same flag and expects `config_error` to name `gab_subject_deks` and `DATABASE_URL`. After the rebase the first error is the production refusal, so those strings are absent. Assert that production plus the env provider, with either flag set, yields `config_error` containing `refused` and an empty `key_provider`. Keep the `DATABASE_URL` assertion on a provider that is allowed in production: `GAB_KEY_PROVIDER=aws-kms` with `GAB_KMS_KEY_ID` and `GAB_KMS_REGION`, `GAB_LEDGER_HYGIENE=1`, and no `DATABASE_URL`. Any ledger test that needs the env provider sets `GAB_ENV=sandbox`.

After each cherry-pick, run the service suite with `GAB_TEST_DATABASE_URL` pointed at localhost. Update that draft's description to name the new base. Leave the pull request a draft.
