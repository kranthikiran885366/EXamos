-- 042_challenge_lifecycle_enhancements.sql
-- Phase 1: Authoritative Challenge Lifecycle
-- Adds institution binding, purpose tracking, and audit capability to examos_attestation_challenges
-- This unifies the challenge lifecycle and ensures single authoritative storage

BEGIN;

-- Add institution_id for tenant isolation
ALTER TABLE examos_attestation_challenges
ADD COLUMN IF NOT EXISTS institution_id varchar(63) NOT NULL DEFAULT '';

-- Add purpose field to distinguish challenge operations
ALTER TABLE examos_attestation_challenges
ADD COLUMN IF NOT EXISTS purpose varchar(32) NOT NULL DEFAULT 're_attestation';

-- Add audit field for who requested the challenge
ALTER TABLE examos_attestation_challenges
ADD COLUMN IF NOT EXISTS created_by varchar(64) NOT NULL DEFAULT '';

-- Add index for tenant-scoped challenge queries
CREATE INDEX IF NOT EXISTS examos_attestation_inst_state_idx
    ON examos_attestation_challenges (institution_id, state)
    WHERE state IN ('PENDING', 'VERIFYING');

-- Add index for purpose-based queries
CREATE INDEX IF NOT EXISTS examos_attestation_purpose_idx
    ON examos_attestation_challenges (purpose, created_at DESC);

-- The original session identifier does not establish tenant ownership.
-- Mark unbound records as legacy instead of inferring an institution.
UPDATE examos_attestation_challenges
SET institution_id = 'legacy'
WHERE institution_id = '';

UPDATE examos_attestation_challenges
SET created_by = 'legacy'
WHERE created_by = '';

-- Challenges created before tenant binding cannot safely be verified.
UPDATE examos_attestation_challenges
SET state = 'STALE',
    failure_code = 'LEGACY_TENANT_BINDING_UNAVAILABLE'
WHERE institution_id = 'legacy'
  AND state IN ('PENDING', 'VERIFYING');

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = to_regclass('public.examos_attestation_challenges')
          AND conname = 'examos_attestation_institution_nonempty_check'
    ) THEN
        ALTER TABLE examos_attestation_challenges
        ADD CONSTRAINT examos_attestation_institution_nonempty_check
        CHECK (institution_id ~ '^[A-Za-z0-9._:-]{1,63}$');
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = to_regclass('public.examos_attestation_challenges')
          AND conname = 'examos_attestation_purpose_check'
    ) THEN
        ALTER TABLE examos_attestation_challenges
        ADD CONSTRAINT examos_attestation_purpose_check
        CHECK (purpose IN ('enrollment', 're_attestation', 'exam_launch'));
    END IF;
END
$$;

-- Update schema migration record
INSERT INTO examos_schema_migrations (component, version)
VALUES ('device_fleet', 42)
ON CONFLICT (component, version) DO NOTHING;

COMMIT;
