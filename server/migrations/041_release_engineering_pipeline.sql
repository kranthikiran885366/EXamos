-- ============================================================================
-- Migration 041: Real OS release engineering pipeline
--
-- Extends the Module 14 release schema (023) with the records needed to prove
-- a release came from an actual build, that its artifacts are the bytes that
-- were built, that its manifest was signed and independently verified, that
-- validation was executed rather than uploaded, and that approval/rollout are
-- bound to that evidence.
--
-- Design rules enforced by this migration:
--   * Build records, artifact records, validation runs and verification gates
--     are append-only history. Nothing here rewrites an existing release.
--   * Private signing keys are never stored in PostgreSQL. Only public keys,
--     key identifiers, fingerprints and lifecycle state are stored.
--   * The seeded 2.0.0 baseline from migration 023 contains placeholder
--     signature/artifact material. It is preserved verbatim but explicitly
--     quarantined as UNVERIFIED so it can never be deployed as trusted.
-- ============================================================================

BEGIN;

-- ---------------------------------------------------------------------------
-- 1. Release: separate operational state from trust state
-- ---------------------------------------------------------------------------
ALTER TABLE os_releases
    ADD COLUMN IF NOT EXISTS validation_profile VARCHAR(32) DEFAULT 'software',
    ADD COLUMN IF NOT EXISTS trust_status VARCHAR(32) DEFAULT 'unverified',
    ADD COLUMN IF NOT EXISTS verification_state VARCHAR(32) DEFAULT 'not_verified',
    ADD COLUMN IF NOT EXISTS verification_at BIGINT,
    ADD COLUMN IF NOT EXISTS verification_expires_at BIGINT,
    ADD COLUMN IF NOT EXISTS verification_digest VARCHAR(128) DEFAULT '',
    ADD COLUMN IF NOT EXISTS manifest_version VARCHAR(32) DEFAULT 'sppio-manifest-v1',
    ADD COLUMN IF NOT EXISTS build_id VARCHAR(64) DEFAULT '',
    ADD COLUMN IF NOT EXISTS signing_algorithm VARCHAR(32) DEFAULT '',
    ADD COLUMN IF NOT EXISTS notes TEXT DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_os_releases_trust ON os_releases(trust_status);
CREATE INDEX IF NOT EXISTS idx_os_releases_verification ON os_releases(verification_state);

-- ---------------------------------------------------------------------------
-- 2. Build records: a release must be traceable to a real build
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS os_release_builds (
    id VARCHAR(64) PRIMARY KEY,
    release_id VARCHAR(64) NOT NULL REFERENCES os_releases(id) ON DELETE CASCADE,
    build_id VARCHAR(128) NOT NULL,
    source_commit VARCHAR(128) NOT NULL,
    source_dirty BOOLEAN NOT NULL DEFAULT TRUE,
    builder_identity VARCHAR(128) NOT NULL,
    build_environment VARCHAR(128) NOT NULL,
    distribution VARCHAR(128) NOT NULL DEFAULT '',
    kernel_version VARCHAR(64) NOT NULL DEFAULT '',
    toolchain_versions TEXT NOT NULL DEFAULT '',
    configuration_digest VARCHAR(128) NOT NULL DEFAULT '',
    started_at BIGINT NOT NULL DEFAULT 0,
    finished_at BIGINT,
    exit_code INTEGER,
    status VARCHAR(32) NOT NULL DEFAULT 'running', -- running, succeeded, failed, cancelled
    output_image_path TEXT DEFAULT '',
    log_reference TEXT DEFAULT '',
    log_sha256 VARCHAR(128) DEFAULT '',
    reproducibility_result VARCHAR(32) DEFAULT 'not_tested',
    reproducibility_digest VARCHAR(128) DEFAULT '',
    created_by VARCHAR(64) NOT NULL DEFAULT '',
    created_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT * 1000),
    CONSTRAINT uq_os_build_release UNIQUE (release_id, build_id)
);
CREATE INDEX IF NOT EXISTS idx_os_build_release ON os_release_builds(release_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_os_build_status ON os_release_builds(status);

-- ---------------------------------------------------------------------------
-- 3. Artifacts: immutable storage reference plus independent verification
-- ---------------------------------------------------------------------------
ALTER TABLE os_release_artifacts
    ADD COLUMN IF NOT EXISTS storage_ref TEXT DEFAULT '',
    ADD COLUMN IF NOT EXISTS media_type VARCHAR(128) DEFAULT '',
    ADD COLUMN IF NOT EXISTS artifact_version VARCHAR(64) DEFAULT '',
    ADD COLUMN IF NOT EXISTS verified BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS verified_at BIGINT,
    ADD COLUMN IF NOT EXISTS verification_note TEXT DEFAULT '',
    ADD COLUMN IF NOT EXISTS immutable BOOLEAN NOT NULL DEFAULT TRUE,
    ADD COLUMN IF NOT EXISTS build_id VARCHAR(64) DEFAULT '';

CREATE UNIQUE INDEX IF NOT EXISTS uq_os_artifact_release_name
    ON os_release_artifacts (release_id, artifact_name);
CREATE INDEX IF NOT EXISTS idx_os_artifacts_verified ON os_release_artifacts(release_id, verified);

-- ---------------------------------------------------------------------------
-- 4. Manifests: canonical form, signature binding, verification time
-- ---------------------------------------------------------------------------
ALTER TABLE os_release_manifests
    ADD COLUMN IF NOT EXISTS canonical_version VARCHAR(32) DEFAULT 'not_canonicalized',
    ADD COLUMN IF NOT EXISTS signed_digest VARCHAR(128) DEFAULT '',
    ADD COLUMN IF NOT EXISTS signing_key_id VARCHAR(64),
    ADD COLUMN IF NOT EXISTS signature_verified_at BIGINT,
    ADD COLUMN IF NOT EXISTS signature_verified BOOLEAN NOT NULL DEFAULT FALSE;

-- ---------------------------------------------------------------------------
-- 5. Signing keys: lifecycle, custody, revocation (public material only)
-- ---------------------------------------------------------------------------
ALTER TABLE os_release_signing_keys
    ADD COLUMN IF NOT EXISTS algorithm VARCHAR(32) DEFAULT 'ed25519',
    ADD COLUMN IF NOT EXISTS custody VARCHAR(64) DEFAULT 'unknown',
    ADD COLUMN IF NOT EXISTS rotated_from VARCHAR(64) REFERENCES os_release_signing_keys(key_id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS revoked_at BIGINT,
    ADD COLUMN IF NOT EXISTS revocation_reason TEXT DEFAULT '';

ALTER TABLE os_release_signing_keys
    DROP CONSTRAINT IF EXISTS chk_os_signing_key_status;
ALTER TABLE os_release_signing_keys
    ADD CONSTRAINT chk_os_signing_key_status
    CHECK (status IN ('active', 'revoked', 'rotated', 'placeholder'));

-- ---------------------------------------------------------------------------
-- 6. Validation runs executed by a real runner (never manually "uploaded")
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS os_release_validation_runs (
    id VARCHAR(64) PRIMARY KEY,
    release_id VARCHAR(64) NOT NULL REFERENCES os_releases(id) ON DELETE CASCADE,
    run_id VARCHAR(128) NOT NULL,
    profile VARCHAR(32) NOT NULL DEFAULT 'software',
    runner_identity VARCHAR(128) NOT NULL DEFAULT '',
    runner_version VARCHAR(64) NOT NULL DEFAULT '',
    environment VARCHAR(128) NOT NULL DEFAULT '',
    started_at BIGINT NOT NULL DEFAULT 0,
    finished_at BIGINT,
    status VARCHAR(32) NOT NULL DEFAULT 'running', -- running, completed, aborted
    result VARCHAR(32) NOT NULL DEFAULT 'NOT_TESTED', -- PASS, FAIL, BLOCKED, NOT_TESTED
    log_reference TEXT DEFAULT '',
    log_sha256 VARCHAR(128) DEFAULT '',
    created_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT * 1000),
    CONSTRAINT uq_os_validation_run UNIQUE (release_id, run_id)
);
CREATE INDEX IF NOT EXISTS idx_os_validation_runs_release
    ON os_release_validation_runs(release_id, started_at DESC);

-- ---------------------------------------------------------------------------
-- 7. Validation results: one row per executed test
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS os_release_validation_results (
    id VARCHAR(64) PRIMARY KEY,
    run_id VARCHAR(64) NOT NULL REFERENCES os_release_validation_runs(id) ON DELETE CASCADE,
    release_id VARCHAR(64) NOT NULL REFERENCES os_releases(id) ON DELETE CASCADE,
    test_id VARCHAR(128) NOT NULL,
    test_name VARCHAR(256) NOT NULL,
    test_version VARCHAR(64) NOT NULL DEFAULT '',
    category VARCHAR(64) NOT NULL, -- build, boot, tpm, security, functional, compatibility
    artifact_ref VARCHAR(256) DEFAULT '',
    environment VARCHAR(128) DEFAULT '',
    started_at BIGINT,
    finished_at BIGINT,
    result VARCHAR(32) NOT NULL, -- PASS, FAIL, BLOCKED, NOT_TESTED
    output TEXT DEFAULT '',
    log_reference TEXT DEFAULT '',
    failure_reason TEXT DEFAULT '',
    executed_by VARCHAR(128) DEFAULT '',
    created_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT * 1000),
    CONSTRAINT uq_os_validation_result UNIQUE (run_id, test_id)
);
CREATE INDEX IF NOT EXISTS idx_os_validation_results_release
    ON os_release_validation_results(release_id, category, result);

-- ---------------------------------------------------------------------------
-- 8. Verification runs and per-gate results (repeatable, auditable)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS os_release_verification_runs (
    id VARCHAR(64) PRIMARY KEY,
    release_id VARCHAR(64) NOT NULL REFERENCES os_releases(id) ON DELETE CASCADE,
    manifest_digest VARCHAR(128) NOT NULL DEFAULT '',
    decision VARCHAR(32) NOT NULL, -- VERIFIED, FAILED, BLOCKED
    gates_passed INTEGER NOT NULL DEFAULT 0,
    gates_failed INTEGER NOT NULL DEFAULT 0,
    gates_blocked INTEGER NOT NULL DEFAULT 0,
    verification_profile VARCHAR(32) NOT NULL DEFAULT 'software',
    verifier_identity VARCHAR(64) NOT NULL DEFAULT '',
    detail TEXT DEFAULT '',
    created_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)
);
CREATE INDEX IF NOT EXISTS idx_os_verification_runs_release
    ON os_release_verification_runs(release_id, created_at DESC);

CREATE TABLE IF NOT EXISTS os_release_verification_gates (
    id VARCHAR(64) PRIMARY KEY,
    verification_id VARCHAR(64) NOT NULL REFERENCES os_release_verification_runs(id) ON DELETE CASCADE,
    gate_id VARCHAR(64) NOT NULL,
    gate_name VARCHAR(256) NOT NULL,
    mandatory BOOLEAN NOT NULL DEFAULT TRUE,
    result VARCHAR(32) NOT NULL, -- PASS, FAIL, BLOCKED, NOT_APPLICABLE
    evidence TEXT DEFAULT '',
    created_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)
);
CREATE INDEX IF NOT EXISTS idx_os_verification_gates_run
    ON os_release_verification_gates(verification_id);

-- ---------------------------------------------------------------------------
-- 9. SBOM records bound to a release artifact
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS os_release_sbom (
    id VARCHAR(64) PRIMARY KEY,
    release_id VARCHAR(64) NOT NULL REFERENCES os_releases(id) ON DELETE CASCADE,
    format VARCHAR(32) NOT NULL, -- cyclonedx, spdx
    format_version VARCHAR(32) NOT NULL DEFAULT '',
    document_sha256 VARCHAR(128) NOT NULL,
    storage_ref TEXT NOT NULL,
    component_count INTEGER NOT NULL DEFAULT 0,
    generator VARCHAR(128) NOT NULL DEFAULT '',
    generator_version VARCHAR(64) NOT NULL DEFAULT '',
    generated_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT * 1000),
    CONSTRAINT uq_os_sbom_release UNIQUE (release_id)
);

-- ---------------------------------------------------------------------------
-- 10. Vulnerability scan + findings (real scanner output only)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS os_release_vulnerability_scans (
    id VARCHAR(64) PRIMARY KEY,
    release_id VARCHAR(64) NOT NULL REFERENCES os_releases(id) ON DELETE CASCADE,
    scanner_name VARCHAR(64) NOT NULL,
    scanner_version VARCHAR(64) NOT NULL DEFAULT '',
    database_version VARCHAR(128) NOT NULL DEFAULT '',
    scan_config TEXT DEFAULT '',
    started_at BIGINT NOT NULL DEFAULT 0,
    finished_at BIGINT,
    critical_count INTEGER NOT NULL DEFAULT 0,
    high_count INTEGER NOT NULL DEFAULT 0,
    medium_count INTEGER NOT NULL DEFAULT 0,
    low_count INTEGER NOT NULL DEFAULT 0,
    result VARCHAR(32) NOT NULL DEFAULT 'NOT_TESTED', -- PASS, FAIL, BLOCKED, NOT_TESTED
    report_sha256 VARCHAR(128) DEFAULT '',
    report_ref TEXT DEFAULT '',
    created_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)
);
CREATE INDEX IF NOT EXISTS idx_os_vuln_release ON os_release_vulnerability_scans(release_id, created_at DESC);

CREATE TABLE IF NOT EXISTS os_release_vulnerability_findings (
    id VARCHAR(64) PRIMARY KEY,
    scan_id VARCHAR(64) NOT NULL REFERENCES os_release_vulnerability_scans(id) ON DELETE CASCADE,
    component VARCHAR(256) NOT NULL,
    component_version VARCHAR(128) DEFAULT '',
    vulnerability_id VARCHAR(128) NOT NULL,
    severity VARCHAR(16) NOT NULL,
    remediation_status VARCHAR(32) NOT NULL DEFAULT 'open',
    exception_reviewer VARCHAR(64) DEFAULT '',
    exception_reason TEXT DEFAULT '',
    exception_expires_at BIGINT,
    created_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)
);
CREATE INDEX IF NOT EXISTS idx_os_vuln_findings_scan ON os_release_vulnerability_findings(scan_id, severity);

-- ---------------------------------------------------------------------------
-- 11. Approval: bind decision to verification state, record expiry
-- ---------------------------------------------------------------------------
ALTER TABLE os_release_approvals
    ADD COLUMN IF NOT EXISTS verification_id VARCHAR(64),
    ADD COLUMN IF NOT EXISTS manifest_digest VARCHAR(128) DEFAULT '',
    ADD COLUMN IF NOT EXISTS approved_role VARCHAR(64) DEFAULT '',
    ADD COLUMN IF NOT EXISTS expires_at BIGINT,
    ADD COLUMN IF NOT EXISTS revoked_at BIGINT;

-- ---------------------------------------------------------------------------
-- 12. Rollout targets / installation results / boot verification / rollback
-- ---------------------------------------------------------------------------
ALTER TABLE os_deployment_assignments
    ADD COLUMN IF NOT EXISTS attempt INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS downloaded_bytes BIGINT DEFAULT 0,
    ADD COLUMN IF NOT EXISTS hash_verified BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS signature_verified BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS installed_release_id VARCHAR(64) DEFAULT '',
    ADD COLUMN IF NOT EXISTS installed_at BIGINT,
    ADD COLUMN IF NOT EXISTS result VARCHAR(32) DEFAULT 'pending', -- pending, success, failed, rolled_back
    ADD COLUMN IF NOT EXISTS error_reason TEXT DEFAULT '',
    ADD COLUMN IF NOT EXISTS updated_by VARCHAR(64) DEFAULT '';

CREATE TABLE IF NOT EXISTS os_release_boot_verifications (
    id VARCHAR(64) PRIMARY KEY,
    device_id VARCHAR(64) NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    release_id VARCHAR(64) NOT NULL REFERENCES os_releases(id) ON DELETE CASCADE,
    boot_mode VARCHAR(32) DEFAULT 'UEFI',
    secure_boot_state VARCHAR(32) DEFAULT 'unknown', -- enabled, disabled, unknown
    uki_verified BOOLEAN NOT NULL DEFAULT FALSE,
    tpm_quote_verified BOOLEAN NOT NULL DEFAULT FALSE,
    pcr_digest VARCHAR(128) DEFAULT '',
    nonce VARCHAR(128) DEFAULT '',
    evidence_ref TEXT DEFAULT '',
    environment VARCHAR(32) NOT NULL DEFAULT 'virtual', -- virtual, physical
    result VARCHAR(32) NOT NULL DEFAULT 'NOT_TESTED', -- PASS, FAIL, BLOCKED, NOT_TESTED
    detail TEXT DEFAULT '',
    occurred_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)
);
CREATE INDEX IF NOT EXISTS idx_os_boot_verify_device ON os_release_boot_verifications(device_id, occurred_at DESC);

CREATE TABLE IF NOT EXISTS os_release_rollback_records (
    id VARCHAR(64) PRIMARY KEY,
    device_id VARCHAR(64) NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    from_release_id VARCHAR(64) NOT NULL,
    to_release_id VARCHAR(64) NOT NULL REFERENCES os_releases(id),
    anti_downgrade_ok BOOLEAN NOT NULL DEFAULT FALSE,
    authorized_by VARCHAR(64) DEFAULT '',
    reason TEXT NOT NULL DEFAULT '',
    status VARCHAR(32) NOT NULL DEFAULT 'initiated', -- initiated, completed, failed, rejected_downgrade
    evidence_ref TEXT DEFAULT '',
    created_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)
);
CREATE INDEX IF NOT EXISTS idx_os_rollback_device ON os_release_rollback_records(device_id, created_at DESC);

-- ---------------------------------------------------------------------------
-- 13. Immutable pipeline audit trail
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS os_release_audit_events (
    id VARCHAR(64) PRIMARY KEY,
    release_id VARCHAR(64),
    actor VARCHAR(64) NOT NULL DEFAULT '',
    event_type VARCHAR(64) NOT NULL,
    detail TEXT DEFAULT '',
    previous_value TEXT DEFAULT '',
    new_value TEXT DEFAULT '',
    occurred_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)
);
CREATE INDEX IF NOT EXISTS idx_os_release_audit_release
    ON os_release_audit_events(release_id, occurred_at DESC);

CREATE OR REPLACE FUNCTION reject_os_release_audit_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'OS release audit history is append-only';
END;
$$;

DROP TRIGGER IF EXISTS os_release_audit_events_append_only ON os_release_audit_events;
CREATE TRIGGER os_release_audit_events_append_only
    BEFORE UPDATE OR DELETE ON os_release_audit_events
    FOR EACH ROW EXECUTE FUNCTION reject_os_release_audit_mutation();

-- ---------------------------------------------------------------------------
-- 14. Quarantine the placeholder baseline seeded by migration 023.
--
-- Migration 023 inserted a truncated public key, fabricated artifact hashes,
-- a fabricated signature and status='active' for osrel_examos_2_0_base. None
-- of that is verification evidence. Keep the row and all original values, but
-- remove its ability to be treated as trusted or deployable.
-- ---------------------------------------------------------------------------
UPDATE os_release_signing_keys
   SET status = 'placeholder',
       revocation_reason = 'Seeded placeholder with a truncated public key in migration 023; never usable for verification'
 WHERE key_id = 'examos-prod-signing-key-v2'
  AND (
      public_key_pem LIKE '%...%'
      OR key_fingerprint =
         'sha256:d8a9e0f1c2b3a4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9'
  );

UPDATE os_releases
  SET trust_status = 'unverified',
      verification_state = 'not_verified',
      rollback_permitted = FALSE,
      signing_algorithm = '',
      notes = COALESCE(NULLIF(notes, ''), 'Quarantined by migration 041: seeded status, digest, signature and artifacts were placeholders with no build or verification evidence.')
WHERE id = 'osrel_examos_2_0_base'
  AND release_id = 'ExamOS 2.0';

UPDATE os_release_artifacts
  SET verified = FALSE,
      verification_note = 'Placeholder artifact seeded by migration 023; no storage object or build provenance exists.'
WHERE release_id = 'osrel_examos_2_0_base'
  AND COALESCE(storage_ref, '') = '';

UPDATE os_release_manifests
  SET verified = FALSE,
      signature_verified = FALSE,
      signature_verified_at = NULL
WHERE release_id = 'osrel_examos_2_0_base';

UPDATE device_os_releases
  SET status = 'deprecated',
      updated_at = (EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)
WHERE id = 'rel_examos_2.0'
  AND release_version = 'ExamOS 2.0'
  AND signing_key_id = 'examos-prod-key-1'
  AND status = 'active';

INSERT INTO os_release_audit_events (id, release_id, actor, event_type, detail, previous_value, new_value)
SELECT 'osrevaudit_041_quarantine_base',
      'osrel_examos_2_0_base',
      'migration_041',
      'RELEASE_QUARANTINED',
      'Seeded placeholder had no build, artifact, signature or validation evidence; trust removed without deleting history.',
      'active/legacy-status-only',
      'active/unverified'
WHERE EXISTS (SELECT 1 FROM os_releases WHERE id = 'osrel_examos_2_0_base')
 AND NOT EXISTS (SELECT 1 FROM os_release_audit_events WHERE id = 'osrevaudit_041_quarantine_base');

-- ---------------------------------------------------------------------------
-- 15. Grants for dedicated application role
-- ---------------------------------------------------------------------------
DO $$
BEGIN
   IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'examos_app') THEN
      EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO examos_app';
      EXECUTE 'GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO examos_app';
   END IF;
END $$;

INSERT INTO examos_schema_migrations (component, version)
VALUES ('os_releases', 41)
ON CONFLICT (component, version) DO NOTHING;

COMMIT;
