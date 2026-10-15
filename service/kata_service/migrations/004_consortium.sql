-- Fingerprint sightings shared among consortium members.
-- A sighting stores the key fingerprint only. It does not store an agent id,
-- a principal id, an email, or an organization name.

CREATE TABLE IF NOT EXISTS gab_consortium_members (
  member_id TEXT PRIMARY KEY,
  org_id TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS gab_consortium_sightings (
  sighting_id TEXT PRIMARY KEY,
  member_id TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  seen_at TEXT NOT NULL,
  UNIQUE (member_id, fingerprint)
);

CREATE INDEX IF NOT EXISTS gab_consortium_sightings_fp ON gab_consortium_sightings (fingerprint);
