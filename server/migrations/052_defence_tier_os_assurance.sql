-- ============================================================================
-- Migration 052: Defence-Tier OS Security Stack & Common Criteria IC3S EAL4
--
-- Adds persistent server tables for:
--   1. Keylime Linux IMA golden file allowlists & PCR-10 verification logs
--   2. Post-Quantum Cryptography (FIPS 203 ML-KEM-768 & FIPS 204 ML-DSA-65) keys
--   3. Tamper-triggered RAM zeroization & DMA attack receipts
--   4. Per-device defence-tier assurance posture (dm-verity A/B, BPF-LSM,
--      PFR SP 800-193, SELinux MLS, IOMMU/DMA, Behavioral AI, STQC IC3S)
-- ============================================================================

BEGIN;

CREATE TABLE IF NOT EXISTS ima_golden_allowlist (
    id              VARCHAR(64) PRIMARY KEY,
    release_version VARCHAR(64) NOT NULL,
    file_path       TEXT NOT NULL,
    sha256_digest   VARCHAR(64) NOT NULL,
    created_at      BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT * 1000),
    UNIQUE (release_version, file_path)
);

CREATE TABLE IF NOT EXISTS ima_verification_logs (
    id              VARCHAR(64) PRIMARY KEY,
    device_id       VARCHAR(64) NOT NULL,
    pcr10_replayed  VARCHAR(64) NOT NULL,
    pcr10_expected  VARCHAR(64) NOT NULL,
    entry_count     INTEGER NOT NULL DEFAULT 0,
    verified        BOOLEAN NOT NULL DEFAULT FALSE,
    failure_reason  TEXT DEFAULT '',
    verified_at     BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)
);

CREATE INDEX IF NOT EXISTS idx_ima_verif_device ON ima_verification_logs(device_id, verified_at DESC);

CREATE TABLE IF NOT EXISTS pqc_signing_keys (
    key_id          VARCHAR(64) PRIMARY KEY,
    algorithm       VARCHAR(32) NOT NULL CHECK (algorithm IN ('ML-KEM-768', 'ML-DSA-65')),
    fips_standard   VARCHAR(16) NOT NULL CHECK (fips_standard IN ('FIPS-203', 'FIPS-204')),
    public_key_hex  TEXT NOT NULL,
    fingerprint     VARCHAR(128) NOT NULL,
    status          VARCHAR(32) NOT NULL DEFAULT 'active',
    created_at      BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)
);

CREATE TABLE IF NOT EXISTS tamper_zeroization_events (
    id              VARCHAR(64) PRIMARY KEY,
    device_id       VARCHAR(64) NOT NULL,
    trigger_type    VARCHAR(64) NOT NULL,
    fde_scrubbed    BOOLEAN NOT NULL DEFAULT FALSE,
    session_scrubbed BOOLEAN NOT NULL DEFAULT FALSE,
    pqc_scrubbed    BOOLEAN NOT NULL DEFAULT FALSE,
    lockdown_engaged BOOLEAN NOT NULL DEFAULT FALSE,
    receipt_digest  VARCHAR(64) DEFAULT '',
    acknowledged_at BIGINT DEFAULT 0,
    recorded_at     BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)
);

CREATE TABLE IF NOT EXISTS device_defence_posture (
    device_id       VARCHAR(64) PRIMARY KEY,
    expected_pcr10  VARCHAR(64) DEFAULT '',
    ab_active_slot  VARCHAR(8) NOT NULL DEFAULT 'UNKNOWN',
    dm_verity_ok    BOOLEAN NOT NULL DEFAULT FALSE,
    bpf_lsm_active  BOOLEAN NOT NULL DEFAULT FALSE,
    pfr_800_193_ok  BOOLEAN NOT NULL DEFAULT FALSE,
    selinux_mls_ok  BOOLEAN NOT NULL DEFAULT FALSE,
    iommu_dma_ok    BOOLEAN NOT NULL DEFAULT FALSE,
    rust_ai_active  BOOLEAN NOT NULL DEFAULT FALSE,
    airgapped_ready BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at      BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)
);

COMMIT;
