-- External evidence recorded for a KATA decision.
-- A row does not decide. POST /v1/verify still returns the KATA decision.
-- payload_hash is SHA-256 of the signed payload bytes. The raw payload is not stored.
-- Principals stay pseudonymous. Government identifier claim names are refused by the verifier.
-- This file sits outside the auto-applied migrations directory.
-- The service boot path globs only service/kata_service/migrations/*.sql.
-- Applying this file is a separate step. Do not point it at Neon from this change.

CREATE TABLE IF NOT EXISTS gab_external_evidence (
  evidence_id TEXT PRIMARY KEY,
  source TEXT NOT NULL,
  issuer TEXT NOT NULL,
  subject TEXT NOT NULL,
  claims TEXT NOT NULL,
  verified_at TEXT NOT NULL,
  key_id TEXT NOT NULL,
  result TEXT NOT NULL CHECK (result IN ('valid', 'invalid', 'unverifiable')),
  reason TEXT NOT NULL,
  payload_hash TEXT NOT NULL,
  decision_ref TEXT NOT NULL,
  agent_id TEXT,
  agreement_id TEXT,
  action_id TEXT,
  kata_decision TEXT,
  audit_id TEXT,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS gab_external_evidence_decision_idx
  ON gab_external_evidence (decision_ref);

CREATE TABLE IF NOT EXISTS gab_evidence_keys (
  directory_hash TEXT NOT NULL,
  kid TEXT NOT NULL,
  public_jwk TEXT NOT NULL,
  fetched_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  PRIMARY KEY (directory_hash, kid)
);

CREATE INDEX IF NOT EXISTS gab_evidence_keys_expiry_idx
  ON gab_evidence_keys (expires_at);

CREATE TABLE IF NOT EXISTS gab_evidence_nonces (
  issuer TEXT NOT NULL,
  nonce TEXT NOT NULL,
  seen_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  PRIMARY KEY (issuer, nonce)
);

CREATE INDEX IF NOT EXISTS gab_evidence_nonces_expiry_idx
  ON gab_evidence_nonces (expires_at);
