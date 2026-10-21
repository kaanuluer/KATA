-- Caller-attested entity kind. Additive. Null until a caller sends business or personal.
-- 013 and 014 are reserved for the breach register and retention migrations.

ALTER TABLE gab_organizations ADD COLUMN IF NOT EXISTS entity_kind TEXT;
ALTER TABLE gab_agents ADD COLUMN IF NOT EXISTS entity_kind TEXT;
