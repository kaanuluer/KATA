-- Keyed identifiers. Additive. Existing rows keep email_hash and plaintext email.
-- New columns stay null until an operator runs the offline backfill.
-- email_hmac stores v1:<kid>:<hex>. Multiple nulls are allowed on the unique index.

ALTER TABLE gab_logins ADD COLUMN IF NOT EXISTS email_hmac TEXT;
ALTER TABLE gab_logins ADD COLUMN IF NOT EXISTS email_kid TEXT;
ALTER TABLE gab_logins ADD COLUMN IF NOT EXISTS email_ciphertext TEXT;

ALTER TABLE gab_org_logins ADD COLUMN IF NOT EXISTS email_hmac TEXT;
ALTER TABLE gab_org_logins ADD COLUMN IF NOT EXISTS email_kid TEXT;
ALTER TABLE gab_org_logins ADD COLUMN IF NOT EXISTS email_ciphertext TEXT;

ALTER TABLE gab_magic_links ADD COLUMN IF NOT EXISTS subject_hmac TEXT;
ALTER TABLE gab_magic_links ADD COLUMN IF NOT EXISTS subject_kid TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS gab_logins_email_hmac_uidx ON gab_logins (email_hmac);
CREATE UNIQUE INDEX IF NOT EXISTS gab_org_logins_email_hmac_uidx ON gab_org_logins (email_hmac);
