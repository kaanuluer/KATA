-- Off-chain ledger payloads. Additive. The wrapped data key is not stored here.
-- It lives in gab_subject_deks. Deleting that row shreds the live database.
-- A Neon backup includes the wrapped key, so a restore brings it back.

CREATE TABLE IF NOT EXISTS gab_payloads (
  payload_id TEXT PRIMARY KEY,
  subject_ref TEXT NOT NULL,
  payload_hash TEXT NOT NULL,
  ciphertext TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS gab_payloads_subject ON gab_payloads (subject_ref);
