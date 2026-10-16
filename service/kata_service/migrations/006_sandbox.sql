-- Test traffic uses the gab_sandbox schema. Production scores stay in public.

CREATE SCHEMA IF NOT EXISTS gab_sandbox;

ALTER TABLE gab_api_keys ADD COLUMN IF NOT EXISTS environment TEXT NOT NULL DEFAULT 'live';

CREATE TABLE IF NOT EXISTS gab_sandbox.gab_agents (LIKE public.gab_agents INCLUDING ALL);

CREATE TABLE IF NOT EXISTS gab_sandbox.gab_agreements (LIKE public.gab_agreements INCLUDING ALL);

CREATE TABLE IF NOT EXISTS gab_sandbox.gab_reports (LIKE public.gab_reports INCLUDING ALL);

CREATE TABLE IF NOT EXISTS gab_sandbox.gab_inquiries (LIKE public.gab_inquiries INCLUDING ALL);

CREATE TABLE IF NOT EXISTS gab_sandbox.gab_subscriptions (LIKE public.gab_subscriptions INCLUDING ALL);

CREATE TABLE IF NOT EXISTS gab_sandbox.gab_alerts (LIKE public.gab_alerts INCLUDING ALL);

CREATE TABLE IF NOT EXISTS gab_sandbox.gab_disputes (LIKE public.gab_disputes INCLUDING ALL);

CREATE TABLE IF NOT EXISTS gab_sandbox.gab_interactions (LIKE public.gab_interactions INCLUDING ALL);

CREATE TABLE IF NOT EXISTS gab_sandbox.gab_identity_links (LIKE public.gab_identity_links INCLUDING ALL);

CREATE TABLE IF NOT EXISTS gab_sandbox.gab_agent_signals (LIKE public.gab_agent_signals INCLUDING ALL);

CREATE TABLE IF NOT EXISTS gab_sandbox.gab_proofings (LIKE public.gab_proofings INCLUDING ALL);

CREATE TABLE IF NOT EXISTS gab_sandbox.gab_consortium_sightings (LIKE public.gab_consortium_sightings INCLUDING ALL);

CREATE TABLE IF NOT EXISTS gab_sandbox.gab_org_signals (LIKE public.gab_org_signals INCLUDING ALL);
