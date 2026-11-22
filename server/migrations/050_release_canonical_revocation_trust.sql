BEGIN;

ALTER TABLE os_release_manifests
    ADD COLUMN IF NOT EXISTS canonical_payload TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS canonical_version VARCHAR(32) NOT NULL DEFAULT 'not_canonicalized';

CREATE TABLE IF NOT EXISTS os_release_revocations (
    release_id VARCHAR(64) PRIMARY KEY
        REFERENCES os_releases(id) ON DELETE CASCADE,
    manifest_digest VARCHAR(128) NOT NULL,
    authority_key_id VARCHAR(64) NOT NULL,
    authority_key_fingerprint VARCHAR(128) NOT NULL,
    signature_base64 TEXT NOT NULL,
    revoked_at BIGINT NOT NULL,
    reason TEXT NOT NULL DEFAULT ''
);

ALTER TABLE os_release_revocations
    DROP CONSTRAINT IF EXISTS os_release_revocation_digest_check;

ALTER TABLE os_release_revocations
    ADD CONSTRAINT os_release_revocation_digest_check
    CHECK (manifest_digest ~ '^sha256:[0-9a-f]{64}$');

CREATE OR REPLACE FUNCTION reject_os_release_revocation_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'OS release revocation records are append-only'
        USING ERRCODE = '55000';
END;
$$;

DROP TRIGGER IF EXISTS os_release_revocations_append_only
    ON os_release_revocations;
CREATE TRIGGER os_release_revocations_append_only
    BEFORE UPDATE OR DELETE ON os_release_revocations
    FOR EACH ROW EXECUTE FUNCTION reject_os_release_revocation_mutation();

REVOKE INSERT, UPDATE, DELETE ON os_release_revocations FROM PUBLIC;

INSERT INTO examos_schema_migrations(component, version)
VALUES ('os_release_trust', 50)
ON CONFLICT (component, version) DO NOTHING;

COMMIT;
