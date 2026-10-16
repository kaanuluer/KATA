-- Individual portal devices, passkey challenges, and step-up approvals.
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

CREATE TABLE IF NOT EXISTS gab_push_devices (
  device_id TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL,
  endpoint TEXT NOT NULL,
  p256dh TEXT NOT NULL,
  auth_secret TEXT NOT NULL,
  consent_at TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS gab_push_principal ON gab_push_devices (principal_id);

CREATE TABLE IF NOT EXISTS gab_approvals (
  approval_id TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL,
  action_hash TEXT NOT NULL,
  action_document TEXT,
  status TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used_at TEXT,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS gab_approvals_principal ON gab_approvals (principal_id, action_hash);
