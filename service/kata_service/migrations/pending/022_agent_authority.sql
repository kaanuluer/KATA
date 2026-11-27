-- Per-agent authority level and stop flag.
-- gab_agents.status is already active, suspended, or revoked. A non-active
-- status is AGENT_NOT_ACTIVE. score_reasons is rewritten when the agent is
-- scored. Neither column can hold a level and a separate stop.
-- These columns are nullable. NULL level means the agent is unassigned.
-- NULL or 0 authority_stopped means the agent is not stopped. 1 means stopped.
-- This file is not on the boot path. The service globs migrations/*.sql only.
-- Do not apply it from this change. Do not point it at Neon from this change.

ALTER TABLE gab_agents ADD COLUMN IF NOT EXISTS authority_level INTEGER;
ALTER TABLE gab_agents ADD COLUMN IF NOT EXISTS authority_stopped INTEGER;

DO $$
BEGIN
  IF to_regclass('gab_sandbox.gab_agents') IS NOT NULL THEN
    ALTER TABLE gab_sandbox.gab_agents ADD COLUMN IF NOT EXISTS authority_level INTEGER;
    ALTER TABLE gab_sandbox.gab_agents ADD COLUMN IF NOT EXISTS authority_stopped INTEGER;
  END IF;
END $$;
