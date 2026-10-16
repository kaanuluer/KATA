-- Per-organization webhook delivery attempts. The detail column is a short code, never a driver message.

CREATE TABLE IF NOT EXISTS gab_webhook_deliveries (
  delivery_id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL,
  agent_id TEXT NOT NULL,
  alert_id TEXT NOT NULL,
  attempt INTEGER NOT NULL,
  at TEXT NOT NULL,
  outcome TEXT NOT NULL,
  http_status INTEGER,
  detail TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS gab_webhook_deliveries_org ON gab_webhook_deliveries (org_id, at);
