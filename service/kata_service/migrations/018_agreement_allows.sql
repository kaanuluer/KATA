-- Per-ALLOW history. The agreement document keeps a counter and a spend summary.
-- Rows here are the hash-chained charges. The document itself stays size-bounded.

CREATE TABLE IF NOT EXISTS gab_agreement_allows (
  agreement_id TEXT NOT NULL,
  sequence INTEGER NOT NULL,
  action_id TEXT NOT NULL,
  intent_id TEXT,
  outcome TEXT NOT NULL,
  currency TEXT NOT NULL,
  amount TEXT,
  at TEXT NOT NULL,
  entry_hash TEXT NOT NULL,
  idempotency_key TEXT,
  entry TEXT NOT NULL,
  is_test BOOLEAN NOT NULL DEFAULT false,
  PRIMARY KEY (agreement_id, sequence, is_test)
);

CREATE UNIQUE INDEX IF NOT EXISTS gab_agreement_allows_action
  ON gab_agreement_allows (agreement_id, action_id, is_test);

CREATE UNIQUE INDEX IF NOT EXISTS gab_agreement_allows_idempotency
  ON gab_agreement_allows (agreement_id, idempotency_key, is_test)
  WHERE idempotency_key IS NOT NULL;

CREATE INDEX IF NOT EXISTS gab_agreement_allows_window
  ON gab_agreement_allows (agreement_id, is_test, at);
