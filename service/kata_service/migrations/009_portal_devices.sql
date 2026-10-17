-- Individual portal passkeys and ceremony challenges.
-- Applied with the other migrations. Additive. No existing table is rewritten.

CREATE TABLE IF NOT EXISTS gab_passkeys (
  credential_id TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL,
  public_key TEXT NOT NULL,
  sign_count INTEGER NOT NULL,
  label TEXT NOT NULL,
  created_at TEXT NOT NULL,
  last_used_at TEXT
);

CREATE INDEX IF NOT EXISTS gab_passkeys_principal ON gab_passkeys (principal_id);

CREATE TABLE IF NOT EXISTS gab_webauthn_challenges (
  challenge_id TEXT PRIMARY KEY,
  principal_id TEXT,
  kind TEXT NOT NULL,
  challenge TEXT NOT NULL,
  rp_id TEXT NOT NULL,
  origin TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used_at TEXT
);

CREATE INDEX IF NOT EXISTS gab_webauthn_challenge_lookup ON gab_webauthn_challenges (kind, challenge);
