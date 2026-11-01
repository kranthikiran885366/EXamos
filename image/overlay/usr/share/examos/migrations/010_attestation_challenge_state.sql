BEGIN;

CREATE TABLE IF NOT EXISTS examos_attestation_challenges (
    attestation_id varchar(63) PRIMARY KEY
        CHECK (attestation_id ~ '^attest-[A-Fa-f0-9]{32}$'),
    session_id varchar(63) NOT NULL
        CHECK (session_id ~ '^[A-Za-z0-9._:-]{1,63}$'),
    device_id varchar(63) NOT NULL
        CHECK (device_id ~ '^[A-Za-z0-9._:-]{1,63}$'),
    release_id varchar(63) NOT NULL
        CHECK (release_id ~ '^[A-Za-z0-9._:-]{1,63}$'),
    nonce_sha256 char(64) NOT NULL UNIQUE
        CHECK (nonce_sha256 ~ '^[0-9a-f]{64}$'),
    state varchar(16) NOT NULL CHECK (state IN (
        'PENDING', 'VERIFYING', 'TRUSTED', 'FAILED', 'STALE', 'REVOKED'
    )),
    failure_code varchar(63) NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    claimed_at timestamptz,
    verified_at timestamptz,
    CHECK (expires_at > created_at),
    CHECK (state <> 'VERIFYING' OR claimed_at IS NOT NULL),
    CHECK (state <> 'TRUSTED' OR verified_at IS NOT NULL)
);

CREATE INDEX IF NOT EXISTS examos_attestation_session_latest_idx
    ON examos_attestation_challenges (session_id, created_at DESC);
CREATE INDEX IF NOT EXISTS examos_attestation_expiry_idx
    ON examos_attestation_challenges (expires_at)
    WHERE state IN ('PENDING', 'VERIFYING');

INSERT INTO examos_schema_migrations (component, version)
VALUES ('device_fleet', 8)
ON CONFLICT (component, version) DO NOTHING;

COMMIT;
