-- Signals shared by an organization, used to contract collusion clusters.
-- A value is an opaque string supplied by the caller, not a government identifier.

CREATE TABLE IF NOT EXISTS gab_org_signals (
  org_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  value TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (org_id, kind, value)
);

CREATE INDEX IF NOT EXISTS gab_org_signals_lookup ON gab_org_signals (kind, value);
