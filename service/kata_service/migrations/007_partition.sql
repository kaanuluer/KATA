-- Live and test rows share these tables. Existing rows stay live (is_test false).
-- Applied migration files are not edited. The gab_sandbox copy is not this partition.

ALTER TABLE gab_agents ADD COLUMN IF NOT EXISTS is_test BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE gab_agreements ADD COLUMN IF NOT EXISTS is_test BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE gab_reports ADD COLUMN IF NOT EXISTS is_test BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE gab_interactions ADD COLUMN IF NOT EXISTS is_test BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE gab_identity_links ADD COLUMN IF NOT EXISTS is_test BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE gab_agent_signals ADD COLUMN IF NOT EXISTS is_test BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE gab_proofings ADD COLUMN IF NOT EXISTS is_test BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE gab_inquiries ADD COLUMN IF NOT EXISTS is_test BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE gab_subscriptions ADD COLUMN IF NOT EXISTS is_test BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE gab_alerts ADD COLUMN IF NOT EXISTS is_test BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE gab_disputes ADD COLUMN IF NOT EXISTS is_test BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE gab_consortium_sightings ADD COLUMN IF NOT EXISTS is_test BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE gab_org_signals ADD COLUMN IF NOT EXISTS is_test BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE gab_webhook_deliveries ADD COLUMN IF NOT EXISTS is_test BOOLEAN NOT NULL DEFAULT false;

CREATE UNIQUE INDEX IF NOT EXISTS gab_agents_partition ON gab_agents (agent_id, is_test);
CREATE UNIQUE INDEX IF NOT EXISTS gab_agents_fingerprint_partition ON gab_agents (fingerprint, is_test);
CREATE UNIQUE INDEX IF NOT EXISTS gab_agreements_partition ON gab_agreements (agreement_id, is_test);
CREATE UNIQUE INDEX IF NOT EXISTS gab_reports_partition ON gab_reports (reporter_org_id, agent_id, kind, evidence_hash, is_test);
CREATE UNIQUE INDEX IF NOT EXISTS gab_agent_signals_partition ON gab_agent_signals (agent_id, kind, value, is_test);
CREATE UNIQUE INDEX IF NOT EXISTS gab_proofings_partition ON gab_proofings (agent_id, method, evidence_hash, is_test);
CREATE UNIQUE INDEX IF NOT EXISTS gab_subscriptions_partition ON gab_subscriptions (org_id, agent_id, webhook_url, is_test);
CREATE UNIQUE INDEX IF NOT EXISTS gab_sightings_partition ON gab_consortium_sightings (member_id, fingerprint, is_test);
CREATE UNIQUE INDEX IF NOT EXISTS gab_org_signals_partition ON gab_org_signals (org_id, kind, value, is_test);

ALTER TABLE gab_agents DROP CONSTRAINT IF EXISTS gab_agents_pkey;
ALTER TABLE gab_agents DROP CONSTRAINT IF EXISTS gab_agents_fingerprint_key;
ALTER TABLE gab_agreements DROP CONSTRAINT IF EXISTS gab_agreements_pkey;
ALTER TABLE gab_reports DROP CONSTRAINT IF EXISTS gab_reports_reporter_org_id_agent_id_kind_evidence_hash_key;
ALTER TABLE gab_agent_signals DROP CONSTRAINT IF EXISTS gab_agent_signals_pkey;
ALTER TABLE gab_proofings DROP CONSTRAINT IF EXISTS gab_proofings_agent_id_method_evidence_hash_key;
ALTER TABLE gab_subscriptions DROP CONSTRAINT IF EXISTS gab_subscriptions_org_id_agent_id_webhook_url_key;
ALTER TABLE gab_consortium_sightings DROP CONSTRAINT IF EXISTS gab_consortium_sightings_member_id_fingerprint_key;
ALTER TABLE gab_org_signals DROP CONSTRAINT IF EXISTS gab_org_signals_pkey;
