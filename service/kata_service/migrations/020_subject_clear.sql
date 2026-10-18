-- Allow a portal subject removal to clear principal_id while the row stays.
-- Dispute statement is cleared in the same change. The row is not rewritten away.
-- gab_sandbox copies from 006 keep the old NOT NULL until this alter.
-- Removing a row from the live database in this process does not change a backup.
-- A restore can bring the data back.

ALTER TABLE gab_inquiries ALTER COLUMN principal_id DROP NOT NULL;

ALTER TABLE gab_disputes ALTER COLUMN principal_id DROP NOT NULL;

ALTER TABLE gab_sandbox.gab_inquiries ALTER COLUMN principal_id DROP NOT NULL;

ALTER TABLE gab_sandbox.gab_disputes ALTER COLUMN principal_id DROP NOT NULL;
