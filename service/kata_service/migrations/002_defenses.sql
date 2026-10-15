-- Interactions, identity links, and an optional action id on reports.
-- Applied with 001. CREATE and ADD use IF NOT EXISTS so a repeat is safe.

ALTER TABLE gab_reports ADD COLUMN IF NOT EXISTS action_id TEXT;

CREATE TABLE IF NOT EXISTS gab_interactions (
  interaction_id TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL,
  operator_org_id TEXT NOT NULL,
  counterparty_org_id TEXT NOT NULL,
  action_id TEXT NOT NULL,
  amount TEXT,
  currency TEXT,
  agreement_id TEXT,
  at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS gab_interactions_agent ON gab_interactions (agent_id);
CREATE INDEX IF NOT EXISTS gab_interactions_operator ON gab_interactions (operator_org_id);
CREATE INDEX IF NOT EXISTS gab_interactions_counterparty ON gab_interactions (counterparty_org_id);

CREATE TABLE IF NOT EXISTS gab_identity_links (
  link_id TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL,
  linked_agent_id TEXT NOT NULL,
  signal TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS gab_identity_links_agent ON gab_identity_links (agent_id);

CREATE TABLE IF NOT EXISTS gab_agent_signals (
  agent_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  value TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (agent_id, kind, value)
);

CREATE INDEX IF NOT EXISTS gab_agent_signals_lookup ON gab_agent_signals (kind, value);
