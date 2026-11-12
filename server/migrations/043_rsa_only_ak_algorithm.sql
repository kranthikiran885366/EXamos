-- 043_rsa_only_ak_algorithm.sql
-- Phase 3: RSA-only AK algorithm enforcement (Option A)
--
-- The TPM quote verifier (tpm_quote.c) implements RSA RSASSA-SHA256 only.
-- Advertising ECC support at the registration layer while the verifier
-- cannot verify ECC quotes creates a broken enrollment path.
--
-- This migration:
--   1. Rejects any existing ECC keys by marking them revoked.
--   2. Replaces the key_algorithm CHECK constraint with RSA-only values.
--   3. Records the migration.

BEGIN;

-- Step 1: Revoke any ECC keys that were accepted before this policy.
-- These keys can never produce a verifiable quote; keeping them active
-- would allow a device to appear enrolled but always fail attestation.
UPDATE device_attestation_keys
SET status = 'revoked'
WHERE key_algorithm IN ('ECC-P256', 'ECC-P384')
  AND status = 'active';

-- Step 2: Drop the old constraint and add the RSA-only constraint.
ALTER TABLE device_attestation_keys
    DROP CONSTRAINT IF EXISTS device_attestation_keys_key_algorithm_check;

ALTER TABLE device_attestation_keys
    ADD CONSTRAINT device_attestation_keys_key_algorithm_check
    CHECK (key_algorithm IN ('RSA-2048', 'RSA-3072'));

-- Step 3: Record migration.
INSERT INTO examos_schema_migrations (component, version)
VALUES ('device_fleet', 43)
ON CONFLICT (component, version) DO NOTHING;

COMMIT;
