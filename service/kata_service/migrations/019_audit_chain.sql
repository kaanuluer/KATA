-- Additive columns, an index, and a tail pointer for the gab_audit row hash chain.
-- prev_hash of the earliest row is the start node value "start".
-- hash covers the audit columns and prev_hash. The hash is not keyed.
-- Someone with database write access can recompute the chain from the start node.
-- Existing rows are linked by the service when this migration is applied.
-- gab_audit_tail holds the current tail hash so an insert does not scan gab_audit.
-- gab_audit_prev_hash_idx indexes prev_hash. gab_audit_unhashed_idx covers rows
-- whose hash is still null, which is the backfill lookup.

ALTER TABLE gab_audit ADD COLUMN IF NOT EXISTS prev_hash TEXT;
ALTER TABLE gab_audit ADD COLUMN IF NOT EXISTS hash TEXT;
CREATE INDEX IF NOT EXISTS gab_audit_prev_hash_idx ON gab_audit (prev_hash);
CREATE INDEX IF NOT EXISTS gab_audit_unhashed_idx ON gab_audit (at, audit_id) WHERE hash IS NULL;
CREATE TABLE IF NOT EXISTS gab_audit_tail (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  tail_hash TEXT NOT NULL
);
