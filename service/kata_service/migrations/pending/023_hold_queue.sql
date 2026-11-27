-- Human approval queue for a STEP_UP verify. One row is one hold.
-- decision_ref and payload_hash bind the approval to the original decision.
-- A missing table is not an error: verify keeps today's decision.
-- This file is not on the boot path. The service globs migrations/*.sql only.
-- Do not apply it from this change. Do not point it at Neon from this change.

CREATE TABLE IF NOT EXISTS gab_holds (
  hold_id TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL,
  agreement_id TEXT NOT NULL DEFAULT '',
  decision_ref TEXT NOT NULL,
  payload_hash TEXT NOT NULL,
  amount TEXT NOT NULL DEFAULT '',
  currency TEXT NOT NULL DEFAULT '',
  payee TEXT NOT NULL DEFAULT '',
  action_document TEXT NOT NULL,
  intent_id TEXT NOT NULL DEFAULT '',
  kata_decision TEXT NOT NULL,
  status TEXT NOT NULL,
  reviewer_id TEXT,
  decision_reason TEXT,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  decided_at TEXT,
  used_at TEXT,
  is_test BOOLEAN NOT NULL DEFAULT false
);

CREATE INDEX IF NOT EXISTS gab_holds_pending
  ON gab_holds (is_test, status, expires_at);

CREATE INDEX IF NOT EXISTS gab_holds_binding
  ON gab_holds (is_test, decision_ref, payload_hash);
