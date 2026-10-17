-- Wrapped per-person data keys. Additive. Ciphertext is not stored here.
-- subject_ref is a keyed HMAC, not a raw identifier and not an unkeyed hash.
-- The application inserts a row once. A second insert does not replace the key.
-- Only an explicit shred deletes the row.
-- A backup taken before that delete still contains the wrapped key.

CREATE TABLE IF NOT EXISTS gab_subject_deks (
  subject_ref TEXT PRIMARY KEY,
  wrapped_dek TEXT NOT NULL,
  created_at TEXT NOT NULL
);
