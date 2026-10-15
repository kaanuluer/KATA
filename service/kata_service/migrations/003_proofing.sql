-- Evidence records that support a verification claim.
-- key_binding is written at registration. Higher claims need operator_review
-- or institution_attestation before they add points.

CREATE TABLE IF NOT EXISTS gab_proofings (
  proofing_id TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL,
  org_id TEXT NOT NULL,
  method TEXT NOT NULL,
  evidence_hash TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE (agent_id, method, evidence_hash)
);

CREATE INDEX IF NOT EXISTS gab_proofings_agent ON gab_proofings (agent_id);
