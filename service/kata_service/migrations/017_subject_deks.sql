-- Wrapped per-person data keys. Additive. Ciphertext is not stored here.
-- subject_ref is an opaque digest, not a raw identifier.
-- Deleting a row drops the wrapped key from the live database.
-- A backup taken before that delete still contains the wrapped key.

CREATE TABLE IF NOT EXISTS gab_subject_deks (
  subject_ref TEXT PRIMARY KEY,
  wrapped_dek TEXT NOT NULL,
  created_at TEXT NOT NULL
);
