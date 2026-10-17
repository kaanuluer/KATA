-- Step-up approval notices for an individual. Additive. Off unless the host sets the flag.

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
