-- 023_secure_os_release_updates_and_deployment.sql
-- Module 14: Secure OS Release, Updates, Rollback & Deployment Management
-- Verifiable release identity, artifact signing, atomic updates, anti-downgrade rollback,
-- and non-destructive Windows data preservation.

-- 1. OS Release Signing Keys
CREATE TABLE IF NOT EXISTS os_release_signing_keys (
    id VARCHAR(64) PRIMARY KEY,
    key_id VARCHAR(64) UNIQUE NOT NULL,
    key_name VARCHAR(128) NOT NULL,
    public_key_pem TEXT NOT NULL,
    key_fingerprint VARCHAR(128) NOT NULL,
    key_type VARCHAR(32) DEFAULT 'production', -- dev, staging, production
    status VARCHAR(32) DEFAULT 'active', -- active, revoked, rotated
    created_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)
);

-- 2. Authoritative OS Releases
CREATE TABLE IF NOT EXISTS os_releases (
    id VARCHAR(64) PRIMARY KEY,
    release_id VARCHAR(64) UNIQUE NOT NULL,
    version VARCHAR(64) NOT NULL,
    source_commit VARCHAR(64) DEFAULT '',
    build_config TEXT DEFAULT '',
    toolchain_version VARCHAR(64) DEFAULT 'Debian 12 / mkosi 14.1',
    kernel_version VARCHAR(64) NOT NULL DEFAULT '6.6.0-examos',
    minimum_supported_version VARCHAR(64) DEFAULT '1.0.0',
    policy_version VARCHAR(64) DEFAULT '1.0',
    status VARCHAR(32) DEFAULT 'draft', -- draft, built, validated, signed, approved, staged, active, suspended, revoked, retired
    signing_key_id VARCHAR(64) REFERENCES os_release_signing_keys(key_id) ON DELETE SET NULL,
    manifest_digest VARCHAR(128) DEFAULT '',
    manifest_signature TEXT DEFAULT '',
    rollback_permitted BOOLEAN DEFAULT FALSE,
    created_by VARCHAR(64) DEFAULT '',
    approved_by VARCHAR(64) DEFAULT '',
    approved_at BIGINT,
    revoked_by VARCHAR(64) DEFAULT '',
    revoked_at BIGINT,
    revocation_reason TEXT DEFAULT '',
    created_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT * 1000),
    updated_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)
);

CREATE INDEX IF NOT EXISTS idx_os_releases_status ON os_releases(status);
CREATE INDEX IF NOT EXISTS idx_os_releases_version ON os_releases(version);

-- 3. Release Artifacts with Cryptographic Hashes
CREATE TABLE IF NOT EXISTS os_release_artifacts (
    id VARCHAR(64) PRIMARY KEY,
    release_id VARCHAR(64) NOT NULL REFERENCES os_releases(id) ON DELETE CASCADE,
    artifact_name VARCHAR(64) NOT NULL, -- rootfs, uki, kernel, initramfs, manifest, sbom, test_report
    artifact_type VARCHAR(32) NOT NULL, -- image, binary, metadata, document
    sha256_digest VARCHAR(128) NOT NULL,
    size_bytes BIGINT DEFAULT 0,
    download_url TEXT DEFAULT '',
    signature TEXT DEFAULT '',
    created_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)
);

CREATE INDEX IF NOT EXISTS idx_os_artifacts_release ON os_release_artifacts(release_id);

-- 4. Signed Release Manifests
CREATE TABLE IF NOT EXISTS os_release_manifests (
    id VARCHAR(64) PRIMARY KEY,
    release_id VARCHAR(64) UNIQUE NOT NULL REFERENCES os_releases(id) ON DELETE CASCADE,
    manifest_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    manifest_digest VARCHAR(128) NOT NULL,
    signature_algorithm VARCHAR(32) DEFAULT 'rsa-sha256',
    signature_value TEXT NOT NULL,
    verified BOOLEAN DEFAULT FALSE,
    created_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)
);

-- 5. Reviewer Approvals (Separation of Duties)
CREATE TABLE IF NOT EXISTS os_release_approvals (
    id VARCHAR(64) PRIMARY KEY,
    release_id VARCHAR(64) NOT NULL REFERENCES os_releases(id) ON DELETE CASCADE,
    reviewer_id VARCHAR(64) NOT NULL,
    decision VARCHAR(32) NOT NULL, -- approved, rejected
    notes TEXT DEFAULT '',
    created_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)
);

-- 6. Release Automated / Manual Validation Test Results
CREATE TABLE IF NOT EXISTS os_release_test_results (
    id VARCHAR(64) PRIMARY KEY,
    release_id VARCHAR(64) NOT NULL REFERENCES os_releases(id) ON DELETE CASCADE,
    test_type VARCHAR(64) NOT NULL, -- boot_integrity, tpm_attestation, data_preservation_windows, network_boot
    status VARCHAR(32) NOT NULL, -- passed, failed
    details TEXT DEFAULT '',
    executed_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)
);

-- 7. Deployment Groups (Pilot, Campus, General Availability)
CREATE TABLE IF NOT EXISTS os_deployment_groups (
    id VARCHAR(64) PRIMARY KEY,
    institution_id VARCHAR(64) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    group_name VARCHAR(128) NOT NULL,
    target_release_id VARCHAR(64) NOT NULL REFERENCES os_releases(id),
    rollout_stage VARCHAR(32) DEFAULT 'pilot', -- pilot, campus, general
    status VARCHAR(32) DEFAULT 'active', -- active, paused, completed
    max_concurrent_updates INTEGER DEFAULT 10,
    maintenance_window_start VARCHAR(32) DEFAULT '00:00',
    maintenance_window_end VARCHAR(32) DEFAULT '23:59',
    created_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT * 1000),
    updated_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)
);

CREATE INDEX IF NOT EXISTS idx_os_dep_groups_inst ON os_deployment_groups(institution_id, status);

-- 8. Deployment Assignments (Device to Deployment Group)
CREATE TABLE IF NOT EXISTS os_deployment_assignments (
    id VARCHAR(64) PRIMARY KEY,
    group_id VARCHAR(64) NOT NULL REFERENCES os_deployment_groups(id) ON DELETE CASCADE,
    device_id VARCHAR(64) NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    target_release_id VARCHAR(64) NOT NULL REFERENCES os_releases(id),
    status VARCHAR(32) DEFAULT 'assigned', -- assigned, downloading, staged, installed, verified, failed
    assigned_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT * 1000),
    updated_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT * 1000),
    CONSTRAINT uq_dev_group UNIQUE (group_id, device_id)
);

-- 9. Device Update Jobs (Update Engine State Machine)
CREATE TABLE IF NOT EXISTS os_update_jobs (
    id VARCHAR(64) PRIMARY KEY,
    device_id VARCHAR(64) NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    institution_id VARCHAR(64) NOT NULL REFERENCES tenants(id),
    source_release_id VARCHAR(64) DEFAULT '',
    target_release_id VARCHAR(64) NOT NULL REFERENCES os_releases(id),
    status VARCHAR(32) DEFAULT 'AVAILABLE', -- AVAILABLE, DEFERRED, BLOCKED, DOWNLOAD_READY, STAGED, INSTALL_PENDING, VERIFYING, SUCCEEDED, FAILED, RECOVERY_REQUIRED, REVOKED
    progress_pct INTEGER DEFAULT 0,
    error_reason TEXT DEFAULT '',
    started_at BIGINT,
    completed_at BIGINT,
    created_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT * 1000),
    updated_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)
);

CREATE INDEX IF NOT EXISTS idx_os_update_jobs_dev ON os_update_jobs(device_id, status);

-- 10. Update Events & Audit Trail
CREATE TABLE IF NOT EXISTS os_update_events (
    id VARCHAR(64) PRIMARY KEY,
    job_id VARCHAR(64) REFERENCES os_update_jobs(id) ON DELETE SET NULL,
    device_id VARCHAR(64) NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    event_type VARCHAR(64) NOT NULL, -- PRECHECK, DOWNLOAD_STARTED, DOWNLOAD_COMPLETED, SIGNATURE_VERIFIED, HASH_VERIFIED, STAGED, REBOOT_SCHEDULED, VERIFY_SUCCESS, VERIFY_FAILED, BLOCKED_EXAM_ACTIVE, ROLLBACK_INITIATED, DATA_PRESERVATION_VERIFIED
    severity VARCHAR(16) DEFAULT 'INFO', -- INFO, WARNING, ERROR, CRITICAL
    details TEXT DEFAULT '',
    occurred_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)
);

CREATE INDEX IF NOT EXISTS idx_os_events_dev ON os_update_events(device_id, occurred_at DESC);

-- 11. Boot Attempts (Atomic A/B or Live Netboot Verification)
CREATE TABLE IF NOT EXISTS os_boot_attempts (
    id VARCHAR(64) PRIMARY KEY,
    device_id VARCHAR(64) NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    release_id VARCHAR(64) NOT NULL REFERENCES os_releases(id),
    slot VARCHAR(32) DEFAULT 'B', -- A, B, LIVE_NETBOOT
    boot_status VARCHAR(32) NOT NULL, -- SUCCESS, FAILED
    error_message TEXT DEFAULT '',
    attempted_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)
);

-- 12. Recovery & Approved Rollback History (Anti-Downgrade Protection)
CREATE TABLE IF NOT EXISTS os_recovery_events (
    id VARCHAR(64) PRIMARY KEY,
    device_id VARCHAR(64) NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    institution_id VARCHAR(64) NOT NULL REFERENCES tenants(id),
    failed_release_id VARCHAR(64) NOT NULL,
    recovery_release_id VARCHAR(64) NOT NULL REFERENCES os_releases(id),
    requested_by VARCHAR(64) DEFAULT '',
    reason TEXT NOT NULL,
    authorized BOOLEAN DEFAULT TRUE,
    status VARCHAR(32) DEFAULT 'INITIATED', -- INITIATED, RESTORED, REJECTED_DOWNGRADE
    occurred_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)
);

-- 13. Seed Baseline Production Signing Key & ExamOS 2.0 Active Release
INSERT INTO os_release_signing_keys (id, key_id, key_name, public_key_pem, key_fingerprint, key_type, status, created_at)
VALUES (
    'oskey_prod_root_01',
    'examos-prod-signing-key-v2',
    'ExamOS Official Production Release Key 2026',
    '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAx4L3yq0...\n-----END PUBLIC KEY-----',
    'sha256:d8a9e0f1c2b3a4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9',
    'production',
    'active',
    (EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)
) ON CONFLICT (key_id) DO NOTHING;

INSERT INTO os_releases (
    id, release_id, version, source_commit, build_config, toolchain_version,
    kernel_version, minimum_supported_version, policy_version, status,
    signing_key_id, manifest_digest, manifest_signature, rollback_permitted,
    created_by, approved_by, approved_at, created_at, updated_at
)
VALUES (
    'osrel_examos_2_0_base',
    'ExamOS 2.0',
    '2.0.0',
    'git:c0ffee14a2b3c4d5',
    'mkosi-debian-secure-uefi',
    'Debian 12 / mkosi 14.1',
    '6.6.0-examos',
    '1.0.0',
    '1.0',
    'active',
    'examos-prod-signing-key-v2',
    'sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    'MIIEYgYJKoZIhvcNAQcCoIIEUTCCBE0CAQExDzANBglghkgBZQMEAgEFADALBgkq...',
    TRUE,
    'system',
    'root',
    (EXTRACT(EPOCH FROM NOW())::BIGINT * 1000),
    (EXTRACT(EPOCH FROM NOW())::BIGINT * 1000),
    (EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)
) ON CONFLICT (release_id) DO NOTHING;

-- Seed Artifacts for Baseline Release
INSERT INTO os_release_artifacts (id, release_id, artifact_name, artifact_type, sha256_digest, size_bytes, download_url, signature)
VALUES
(
    'art_2_0_rootfs',
    'osrel_examos_2_0_base',
    'rootfs',
    'image',
    'sha256:7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b',
    1073741824,
    'https://releases.examos.org/2.0.0/rootfs.erofs',
    'SIG_ROOTFS_2_0_OK'
),
(
    'art_2_0_uki',
    'osrel_examos_2_0_base',
    'uki',
    'binary',
    'sha256:9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e',
    67108864,
    'https://releases.examos.org/2.0.0/examos.efi',
    'SIG_UKI_2_0_OK'
)
ON CONFLICT (id) DO NOTHING;

-- Grant permissions to examos_app if the role exists (e.g. self-hosted / dedicated environments)
DO $$
BEGIN
   IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'examos_app') THEN
      EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO examos_app';
   END IF;
END $$;

INSERT INTO examos_schema_migrations (component, version)
VALUES ('os_releases', 1)
ON CONFLICT (component, version) DO NOTHING;
