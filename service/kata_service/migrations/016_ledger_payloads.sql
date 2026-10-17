-- Off-chain ledger payloads. Additive. The wrapped data key is not stored here.
-- Destroying the data key outside this database is what makes the ciphertext unreadable.
-- A database backup that also contains the data key does not shred.

CREATE TABLE IF NOT EXISTS gab_payloads (
  payload_id TEXT PRIMARY KEY,
  subject_ref TEXT NOT NULL,
  payload_hash TEXT NOT NULL,
  ciphertext TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS gab_payloads_subject ON gab_payloads (subject_ref);
