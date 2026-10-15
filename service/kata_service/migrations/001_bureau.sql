-- Global Agent Bureau tables. Applied by the service on startup and by the seed script.
-- One Postgres database (DATABASE_URL). No second database is required.

CREATE TABLE IF NOT EXISTS gab_schema_migrations (
  version TEXT PRIMARY KEY,
  applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS gab_organizations (
  org_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  org_type TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS gab_api_keys (
  key_id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL,
  name TEXT NOT NULL,
  prefix TEXT NOT NULL,
  secret_hash TEXT NOT NULL UNIQUE,
  scopes TEXT NOT NULL,
  created_at TEXT NOT NULL,
  revoked_at TEXT,
  rotated_from TEXT
);

CREATE TABLE IF NOT EXISTS gab_audit (
  audit_id TEXT PRIMARY KEY,
  at TEXT NOT NULL,
  org_id TEXT,
  key_id TEXT,
  method TEXT NOT NULL,
  path TEXT NOT NULL,
  status INTEGER NOT NULL,
  purpose_code TEXT,
  agent_id TEXT
);

CREATE TABLE IF NOT EXISTS gab_rate (
  subject TEXT NOT NULL,
  window_start TEXT NOT NULL,
  hits INTEGER NOT NULL,
  PRIMARY KEY (subject, window_start)
);

CREATE TABLE IF NOT EXISTS gab_principals (
  principal_id TEXT PRIMARY KEY,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS gab_logins (
  email_hash TEXT PRIMARY KEY,
  email TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS gab_magic_links (
  token_hash TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  subject_hash TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used_at TEXT
);

CREATE TABLE IF NOT EXISTS gab_sessions (
  token_hash TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  subject_id TEXT NOT NULL,
  expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS gab_org_logins (
  email_hash TEXT PRIMARY KEY,
  email TEXT NOT NULL,
  org_id TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS gab_agents (
  agent_id TEXT PRIMARY KEY,
  operator_org_id TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  status TEXT NOT NULL,
  verification_level TEXT NOT NULL,
  algorithm TEXT NOT NULL,
  fingerprint TEXT NOT NULL UNIQUE,
  public_key TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  score INTEGER NOT NULL,
  score_reasons TEXT NOT NULL,
  cold_start INTEGER NOT NULL,
  principal_public_key TEXT
);

CREATE TABLE IF NOT EXISTS gab_agreements (
  agreement_id TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL,
  document TEXT NOT NULL,
  status TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS gab_reports (
  report_id TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL,
  reporter_org_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  evidence_hash TEXT NOT NULL,
  summary TEXT NOT NULL,
  outcome TEXT,
  created_at TEXT NOT NULL,
  excluded INTEGER NOT NULL DEFAULT 0,
  UNIQUE (reporter_org_id, agent_id, kind, evidence_hash)
);

CREATE TABLE IF NOT EXISTS gab_inquiries (
  inquiry_id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL,
  agent_id TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  purpose_code TEXT NOT NULL,
  at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS gab_subscriptions (
  subscription_id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL,
  agent_id TEXT NOT NULL,
  webhook_url TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE (org_id, agent_id, webhook_url)
);

CREATE TABLE IF NOT EXISTS gab_alerts (
  alert_id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL,
  agent_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  document TEXT NOT NULL,
  created_at TEXT NOT NULL,
  delivered INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS gab_disputes (
  dispute_id TEXT PRIMARY KEY,
  report_id TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  statement TEXT NOT NULL,
  status TEXT NOT NULL,
  outcome TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS gab_inquiries_principal ON gab_inquiries (principal_id);
CREATE INDEX IF NOT EXISTS gab_reports_agent ON gab_reports (agent_id);
CREATE INDEX IF NOT EXISTS gab_agents_operator ON gab_agents (operator_org_id);
