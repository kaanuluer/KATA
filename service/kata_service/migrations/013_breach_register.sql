-- Breach register. Additive. Types of data only. Append-only.
-- retain_until is detected_at plus 5 years. Rows are not deleted here.
-- A restricted database role is an operator grant. This file does not create one:
-- the deployment role and grants are unknown, and the table owner can still drop a trigger.

CREATE TABLE IF NOT EXISTS gab_breach_register (
  seq BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  event_id TEXT NOT NULL UNIQUE,
  detected_at TEXT NOT NULL,
  data_types TEXT NOT NULL,
  scope_count INTEGER,
  note_hash TEXT,
  prev_hash TEXT NOT NULL,
  entry_hash TEXT NOT NULL,
  retain_until TEXT NOT NULL
);

CREATE OR REPLACE FUNCTION gab_reject_breach_mutation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'gab_breach_register is append-only'; RETURN NULL; END; $$;

DROP TRIGGER IF EXISTS gab_breach_register_append_only ON gab_breach_register;

CREATE TRIGGER gab_breach_register_append_only
BEFORE UPDATE OR DELETE ON gab_breach_register
FOR EACH ROW
EXECUTE FUNCTION gab_reject_breach_mutation();

CREATE TABLE IF NOT EXISTS gab_register_access_log (
  seq BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  access_id TEXT NOT NULL UNIQUE,
  at TEXT NOT NULL,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  prev_hash TEXT NOT NULL,
  entry_hash TEXT NOT NULL
);

CREATE OR REPLACE FUNCTION gab_reject_register_access_mutation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'gab_register_access_log is append-only'; RETURN NULL; END; $$;

DROP TRIGGER IF EXISTS gab_register_access_append_only ON gab_register_access_log;

CREATE TRIGGER gab_register_access_append_only
BEFORE UPDATE OR DELETE ON gab_register_access_log
FOR EACH ROW
EXECUTE FUNCTION gab_reject_register_access_mutation();
