-- Audit rows record which partition handled the request. Existing rows stay live.

ALTER TABLE gab_audit ADD COLUMN IF NOT EXISTS environment TEXT NOT NULL DEFAULT 'live';
