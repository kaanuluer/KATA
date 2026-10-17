-- Consent events. Additive. Append-only by trigger.
-- Existing push rows are not copied here. That copy is an offline script.

CREATE TABLE IF NOT EXISTS gab_consent_events (
  seq BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  event_id TEXT NOT NULL UNIQUE,
  principal_id TEXT NOT NULL,
  purpose TEXT NOT NULL,
  granted BOOLEAN NOT NULL,
  text_version TEXT NOT NULL,
  text_sha256 TEXT NOT NULL,
  at TEXT NOT NULL,
  source_ref TEXT,
  prev_hash TEXT NOT NULL,
  entry_hash TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS gab_consent_source_ref ON gab_consent_events (source_ref);
CREATE INDEX IF NOT EXISTS gab_consent_principal ON gab_consent_events (principal_id, purpose);

CREATE OR REPLACE FUNCTION gab_reject_consent_mutation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'gab_consent_events is append-only'; RETURN NULL; END; $$;

DROP TRIGGER IF EXISTS gab_consent_events_append_only ON gab_consent_events;

CREATE TRIGGER gab_consent_events_append_only
BEFORE UPDATE OR DELETE ON gab_consent_events
FOR EACH ROW
EXECUTE FUNCTION gab_reject_consent_mutation();
