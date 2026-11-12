-- Register EK provenance and one-time TPM credential activation storage.
BEGIN;

CREATE TABLE IF NOT EXISTS device_ek_certificates (
    id VARCHAR(64) PRIMARY KEY,
    device_id VARCHAR(64) NOT NULL,
    institution_id VARCHAR(64) NOT NULL,
    ek_certificate_pem TEXT NOT NULL,
    ek_certificate_chain TEXT,
    ek_public_key_pem TEXT NOT NULL,
    ek_public_key_fingerprint VARCHAR(64) NOT NULL,
    manufacturer VARCHAR(128),
    model VARCHAR(128),
    certificate_issuer VARCHAR(256),
    certificate_serial VARCHAR(128),
    certificate_not_before BIGINT,
    certificate_not_after BIGINT,
    trust_status VARCHAR(32) NOT NULL DEFAULT 'pending'
        CHECK (trust_status IN ('pending', 'verified', 'untrusted', 'expired', 'revoked')),
    trust_anchor_id VARCHAR(64),
    verification_details TEXT,
    created_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM clock_timestamp())::BIGINT * 1000),
    updated_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM clock_timestamp())::BIGINT * 1000)
);
CREATE INDEX IF NOT EXISTS idx_ek_cert_device ON device_ek_certificates(device_id);
CREATE INDEX IF NOT EXISTS idx_ek_cert_inst ON device_ek_certificates(institution_id);
CREATE INDEX IF NOT EXISTS idx_ek_cert_status ON device_ek_certificates(trust_status);
CREATE INDEX IF NOT EXISTS idx_ek_cert_fingerprint ON device_ek_certificates(ek_public_key_fingerprint);

ALTER TABLE device_attestation_keys
    ADD COLUMN IF NOT EXISTS ak_public_area_hex TEXT,
    ADD COLUMN IF NOT EXISTS ak_name_hex VARCHAR(68),
    ADD COLUMN IF NOT EXISTS ak_qualified_name_hex VARCHAR(68),
    ADD COLUMN IF NOT EXISTS ak_template_id VARCHAR(64),
    ADD COLUMN IF NOT EXISTS provenance_status VARCHAR(32) NOT NULL DEFAULT 'pending'
        CHECK (provenance_status IN ('pending', 'template_valid', 'template_invalid', 'verified', 'failed')),
    ADD COLUMN IF NOT EXISTS provenance_details TEXT;

CREATE TABLE IF NOT EXISTS device_credential_activations (
    id VARCHAR(64) PRIMARY KEY,
    device_id VARCHAR(64) NOT NULL,
    institution_id VARCHAR(64) NOT NULL,
    ak_name_hex VARCHAR(68) NOT NULL,
    credential_blob_hex TEXT NOT NULL,
    credential_secret_hash VARCHAR(64) NOT NULL CHECK (credential_secret_hash ~ '^[0-9a-f]{64}$'),
    status VARCHAR(32) NOT NULL DEFAULT 'pending',
    activation_error VARCHAR(64),
    created_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM clock_timestamp())::BIGINT * 1000),
    expires_at BIGINT NOT NULL,
    activated_at BIGINT
);
ALTER TABLE device_credential_activations
    ADD COLUMN IF NOT EXISTS activation_error VARCHAR(64);
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'device_credential_activations'::regclass
          AND conname = 'device_credential_activations_status_check'
    ) THEN
        ALTER TABLE device_credential_activations
            DROP CONSTRAINT device_credential_activations_status_check;
    END IF;
    ALTER TABLE device_credential_activations
        ADD CONSTRAINT device_credential_activations_status_check
        CHECK (status IN ('pending', 'verifying', 'activated', 'failed', 'expired'));
END
$$;
CREATE INDEX IF NOT EXISTS idx_cred_act_device ON device_credential_activations(device_id);
CREATE INDEX IF NOT EXISTS idx_cred_act_ak_name ON device_credential_activations(ak_name_hex);
CREATE INDEX IF NOT EXISTS idx_cred_act_status ON device_credential_activations(status);
CREATE UNIQUE INDEX IF NOT EXISTS idx_cred_act_one_open_per_device
    ON device_credential_activations(device_id) WHERE status IN ('pending', 'verifying');

CREATE TABLE IF NOT EXISTS device_ak_templates (
    id VARCHAR(64) PRIMARY KEY,
    template_name VARCHAR(128) NOT NULL,
    name_algorithm VARCHAR(32) NOT NULL DEFAULT 'sha256',
    public_key_algorithm VARCHAR(32) NOT NULL,
    signing_scheme VARCHAR(32) NOT NULL,
    key_size_bits INT,
    curve VARCHAR(32),
    required_attributes TEXT NOT NULL,
    forbidden_attributes TEXT,
    description TEXT,
    status VARCHAR(32) NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'deprecated', 'revoked')),
    created_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM clock_timestamp())::BIGINT * 1000)
);
CREATE INDEX IF NOT EXISTS idx_ak_template_status ON device_ak_templates(status);
INSERT INTO device_ak_templates
    (id, template_name, name_algorithm, public_key_algorithm, signing_scheme,
     key_size_bits, required_attributes, forbidden_attributes, description, status)
VALUES
    ('tpl_rsa2048_ak', 'RSA-2048 Attestation Key', 'sha256', 'rsa', 'rsassa',
     2048, 'fixedTPM,fixedParent,restricted,sign,sensitiveDataOrigin,userWithAuth',
     'decrypt', 'RSA-2048 TPM attestation key', 'active'),
    ('tpl_rsa3072_ak', 'RSA-3072 Attestation Key', 'sha256', 'rsa', 'rsassa',
     3072, 'fixedTPM,fixedParent,restricted,sign,sensitiveDataOrigin,userWithAuth',
     'decrypt', 'RSA-3072 TPM attestation key', 'active')
ON CONFLICT (id) DO NOTHING;

CREATE TABLE IF NOT EXISTS device_trust_anchors (
    id VARCHAR(64) PRIMARY KEY,
    anchor_name VARCHAR(128) NOT NULL,
    anchor_type VARCHAR(32) NOT NULL
        CHECK (anchor_type IN ('manufacturer_root', 'intermediate_ca', 'institutional')),
    certificate_pem TEXT NOT NULL,
    certificate_fingerprint VARCHAR(64) NOT NULL,
    parent_anchor_id VARCHAR(64),
    status VARCHAR(32) NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'revoked', 'expired')),
    valid_from BIGINT,
    valid_until BIGINT,
    created_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM clock_timestamp())::BIGINT * 1000)
);
CREATE INDEX IF NOT EXISTS idx_trust_anchor_status ON device_trust_anchors(status);
CREATE INDEX IF NOT EXISTS idx_trust_anchor_fp ON device_trust_anchors(certificate_fingerprint);

INSERT INTO examos_schema_migrations(component, version)
VALUES ('device_fleet', 44)
ON CONFLICT (component, version) DO NOTHING;
COMMIT;
