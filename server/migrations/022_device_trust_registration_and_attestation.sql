-- 022_device_trust_registration_and_attestation.sql
-- Module 13: Device Trust, Registration & Attestation
-- Unified enterprise device identity, registration lifecycle, boot verification,
-- TPM attestation challenge-response, device trust policy engine, assignments, and audit logging.

-- 1. Extend existing devices table with enterprise Module 13 fields
ALTER TABLE devices ADD COLUMN IF NOT EXISTS institution_id VARCHAR(64) DEFAULT '';
ALTER TABLE devices ADD COLUMN IF NOT EXISTS campus_id VARCHAR(64) DEFAULT '';
ALTER TABLE devices ADD COLUMN IF NOT EXISTS device_name VARCHAR(128) DEFAULT '';
ALTER TABLE devices ADD COLUMN IF NOT EXISTS device_category VARCHAR(32) DEFAULT 'lab_pc';
ALTER TABLE devices ADD COLUMN IF NOT EXISTS manufacturer VARCHAR(128) DEFAULT 'Generic';
ALTER TABLE devices ADD COLUMN IF NOT EXISTS model VARCHAR(128) DEFAULT 'Standard';
ALTER TABLE devices ADD COLUMN IF NOT EXISTS cpu_arch VARCHAR(64) DEFAULT 'x86_64';
ALTER TABLE devices ADD COLUMN IF NOT EXISTS boot_mode VARCHAR(32) DEFAULT 'UEFI';
ALTER TABLE devices ADD COLUMN IF NOT EXISTS secure_boot_state VARCHAR(32) DEFAULT 'enabled';
ALTER TABLE devices ADD COLUMN IF NOT EXISTS tpm_present BOOLEAN DEFAULT TRUE;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS tpm_version VARCHAR(32) DEFAULT '2.0';
ALTER TABLE devices ADD COLUMN IF NOT EXISTS os_release_id VARCHAR(64) DEFAULT 'ExamOS 2.0';
ALTER TABLE devices ADD COLUMN IF NOT EXISTS kernel_version VARCHAR(64) DEFAULT '6.6.0-examos';
ALTER TABLE devices ADD COLUMN IF NOT EXISTS last_contact_at BIGINT;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS last_attestation_at BIGINT;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS created_at BIGINT DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT * 1000);
ALTER TABLE devices ADD COLUMN IF NOT EXISTS updated_at BIGINT DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT * 1000);

UPDATE devices SET institution_id = tenant_id WHERE institution_id IS NULL OR institution_id = '';

CREATE INDEX IF NOT EXISTS idx_devices_inst ON devices (institution_id);
CREATE INDEX IF NOT EXISTS idx_devices_campus ON devices (campus_id);
CREATE INDEX IF NOT EXISTS idx_devices_status ON devices (status);
ALTER TABLE device_assignments DROP CONSTRAINT IF EXISTS fk_da_assigner;

-- 2. Device Registration Lifecycle Records
CREATE TABLE IF NOT EXISTS device_registrations (
    id VARCHAR(64) PRIMARY KEY,
    device_id VARCHAR(64) NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    institution_id VARCHAR(64) NOT NULL,
    requested_by VARCHAR(64) NOT NULL,
    decision VARCHAR(32) NOT NULL DEFAULT 'pending' CHECK (decision IN ('pending', 'approved', 'rejected')),
    decided_by VARCHAR(64) NOT NULL DEFAULT '',
    rejection_reason VARCHAR(256) NOT NULL DEFAULT '',
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_device_reg_dev ON device_registrations (device_id);

-- 3. Extend device_assignments
ALTER TABLE device_assignments ADD COLUMN IF NOT EXISTS assignment_type VARCHAR(32) DEFAULT 'student';
ALTER TABLE device_assignments ADD COLUMN IF NOT EXISTS assigned_student_id VARCHAR(64) DEFAULT '';
ALTER TABLE device_assignments ADD COLUMN IF NOT EXISTS assigned_exam_id VARCHAR(64) DEFAULT '';
ALTER TABLE device_assignments ADD COLUMN IF NOT EXISTS start_time BIGINT DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT * 1000);
ALTER TABLE device_assignments ADD COLUMN IF NOT EXISTS end_time BIGINT;
ALTER TABLE device_assignments ADD COLUMN IF NOT EXISTS created_at BIGINT DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT * 1000);

CREATE INDEX IF NOT EXISTS idx_dev_assign_stu ON device_assignments (assigned_student_id);

-- 4. Approved OS Releases
CREATE TABLE IF NOT EXISTS device_os_releases (
    id VARCHAR(64) PRIMARY KEY,
    release_version VARCHAR(64) NOT NULL UNIQUE,
    release_name VARCHAR(128) NOT NULL,
    signing_key_id VARCHAR(64) NOT NULL DEFAULT 'examos-prod-key-1',
    status VARCHAR(32) NOT NULL DEFAULT 'active' CHECK (status IN ('draft', 'active', 'deprecated', 'revoked')),
    min_supported BOOLEAN NOT NULL DEFAULT TRUE,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);

-- 5. OS Release Artifacts (Signed Digests)
CREATE TABLE IF NOT EXISTS device_release_artifacts (
    id VARCHAR(64) PRIMARY KEY,
    release_id VARCHAR(64) NOT NULL REFERENCES device_os_releases(id) ON DELETE CASCADE,
    artifact_type VARCHAR(32) NOT NULL CHECK (artifact_type IN ('kernel', 'initramfs', 'uki', 'rootfs', 'iso')),
    artifact_hash_sha256 VARCHAR(64) NOT NULL,
    signature VARCHAR(512) NOT NULL DEFAULT '',
    created_at BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_dev_rel_art ON device_release_artifacts (release_id);

-- 6. Enrolled Device Attestation Keys (AK Public Keys)
CREATE TABLE IF NOT EXISTS device_attestation_keys (
    id VARCHAR(64) PRIMARY KEY,
    device_id VARCHAR(64) NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    key_name VARCHAR(64) NOT NULL DEFAULT 'AK',
    key_algorithm VARCHAR(32) NOT NULL DEFAULT 'RSA-2048' CHECK (key_algorithm IN ('RSA-2048', 'RSA-3072', 'ECC-P256', 'ECC-P384')),
    public_key_pem TEXT NOT NULL,
    public_key_fingerprint VARCHAR(64) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked', 'expired')),
    enrolled_at BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_dev_ak_dev ON device_attestation_keys (device_id);

-- 7. Attestation Challenges (Nonce Generation & Anti-Replay)
CREATE TABLE IF NOT EXISTS device_attestation_challenges (
    id VARCHAR(64) PRIMARY KEY,
    device_id VARCHAR(64) NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    nonce VARCHAR(128) NOT NULL UNIQUE,
    used BOOLEAN NOT NULL DEFAULT FALSE,
    expires_at BIGINT NOT NULL,
    created_at BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_dev_att_nonce ON device_attestation_challenges (nonce);

-- 8. Attestation Evidence & Verification
CREATE TABLE IF NOT EXISTS device_attestation_evidence (
    id VARCHAR(64) PRIMARY KEY,
    device_id VARCHAR(64) NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    challenge_id VARCHAR(64) NOT NULL,
    ak_key_id VARCHAR(64) NOT NULL,
    quote_signature TEXT NOT NULL,
    pcr_digest VARCHAR(64) NOT NULL,
    pcr_values_json TEXT NOT NULL DEFAULT '{}',
    measurement_log_hash VARCHAR(64) NOT NULL DEFAULT '',
    verification_result VARCHAR(32) NOT NULL CHECK (verification_result IN ('TRUSTED', 'FAILED', 'STALE', 'UNVERIFIED')),
    failure_reason VARCHAR(256) NOT NULL DEFAULT '',
    verified_at BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_dev_att_ev ON device_attestation_evidence (device_id);

-- 9. Device Trust Policies
CREATE TABLE IF NOT EXISTS device_trust_policies (
    id VARCHAR(64) PRIMARY KEY,
    institution_id VARCHAR(64) NOT NULL,
    policy_name VARCHAR(128) NOT NULL,
    version INT NOT NULL DEFAULT 1,
    require_registration BOOLEAN NOT NULL DEFAULT TRUE,
    require_admin_approval BOOLEAN NOT NULL DEFAULT FALSE,
    require_tpm BOOLEAN NOT NULL DEFAULT TRUE,
    require_secure_boot BOOLEAN NOT NULL DEFAULT TRUE,
    require_approved_release BOOLEAN NOT NULL DEFAULT TRUE,
    max_evidence_age_sec INT NOT NULL DEFAULT 300,
    allowed_device_categories VARCHAR(256) NOT NULL DEFAULT 'lab_pc,institution_laptop,personal_laptop,kiosk_appliance',
    status VARCHAR(32) NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'approved', 'active', 'retired')),
    approved_by VARCHAR(64) NOT NULL DEFAULT '',
    approved_at BIGINT,
    activated_at BIGINT,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_dev_policy_inst ON device_trust_policies (institution_id, status);

-- 10. Device Trust Decisions (Central Engine Outputs)
CREATE TABLE IF NOT EXISTS device_trust_decisions (
    id VARCHAR(64) PRIMARY KEY,
    device_id VARCHAR(64) NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    policy_id VARCHAR(64) NOT NULL,
    policy_version INT NOT NULL DEFAULT 1,
    outcome VARCHAR(32) NOT NULL CHECK (outcome IN ('ALLOW', 'DENY', 'PENDING', 'REASSESS', 'QUARANTINE', 'UNSUPPORTED')),
    passed_checks TEXT NOT NULL DEFAULT '[]',
    failed_checks TEXT NOT NULL DEFAULT '[]',
    reason VARCHAR(512) NOT NULL DEFAULT '',
    evaluated_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_dev_dec_dev ON device_trust_decisions (device_id);

-- 11. Device Security Events
CREATE TABLE IF NOT EXISTS device_security_events (
    id VARCHAR(64) PRIMARY KEY,
    device_id VARCHAR(64) NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    event_type VARCHAR(64) NOT NULL,
    severity VARCHAR(32) NOT NULL DEFAULT 'WARNING' CHECK (severity IN ('INFO', 'WARNING', 'ERROR', 'CRITICAL')),
    details TEXT NOT NULL DEFAULT '',
    created_at BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_dev_sec_ev ON device_security_events (device_id);

-- 12. Device Audit Events
CREATE TABLE IF NOT EXISTS device_audit_events (
    id VARCHAR(64) PRIMARY KEY,
    device_id VARCHAR(64) NOT NULL,
    institution_id VARCHAR(64) NOT NULL,
    actor_id VARCHAR(64) NOT NULL,
    action VARCHAR(64) NOT NULL,
    details TEXT NOT NULL DEFAULT '',
    created_at BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_dev_audit_dev ON device_audit_events (device_id);

-- Seed Initial Approved ExamOS Release
INSERT INTO device_os_releases (id, release_version, release_name, signing_key_id, status, min_supported, created_at, updated_at)
VALUES ('rel_examos_2.0', 'ExamOS 2.0', 'ExamOS 2.0 Secure Kiosk Appliance Release', 'examos-prod-key-1', 'active', TRUE, EXTRACT(EPOCH FROM NOW())::BIGINT * 1000, EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)
ON CONFLICT (release_version) DO NOTHING;

-- Seed Default Active Policy for Default Institutions
INSERT INTO device_trust_policies (id, institution_id, policy_name, version, require_registration, require_admin_approval, require_tpm, require_secure_boot, require_approved_release, max_evidence_age_sec, status, approved_by, approved_at, activated_at, created_at, updated_at)
VALUES ('dtpol_default_vignan', 'inst_vignan', 'Vignan Standard Examination Device Policy', 1, TRUE, FALSE, TRUE, TRUE, TRUE, 600, 'active', 'usr_root', EXTRACT(EPOCH FROM NOW())::BIGINT * 1000, EXTRACT(EPOCH FROM NOW())::BIGINT * 1000, EXTRACT(EPOCH FROM NOW())::BIGINT * 1000, EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)
ON CONFLICT (id) DO NOTHING;

INSERT INTO examos_schema_migrations (component, version)
VALUES ('device_fleet', 10)
ON CONFLICT (component, version) DO NOTHING;
