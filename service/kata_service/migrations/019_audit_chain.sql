-- Additive columns for the gab_audit row hash chain.
-- prev_hash of the earliest row is the start node value "start".
-- hash covers the audit columns and prev_hash.
-- Existing rows are linked by the service when this migration is applied.
-- The chain is tamper-evident when a later check walks these columns.

ALTER TABLE gab_audit ADD COLUMN IF NOT EXISTS prev_hash TEXT;
ALTER TABLE gab_audit ADD COLUMN IF NOT EXISTS hash TEXT;
