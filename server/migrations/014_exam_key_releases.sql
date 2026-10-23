BEGIN;

-- Migration 014: durable, sealed exam-key release records.
--
-- The exam decryption key is generated only after a successful TPM quote
-- verification. It must survive a server restart so that a trusted session
-- can still obtain its key, so it cannot live in process memory only.
--
-- It is never stored in the clear. The key is sealed with AES-256-GCM under
-- a key-encryption key derived from EXAMOS_EXAM_KEY_KEK. The sealed record
-- is bound to the attestation challenge that produced it, so a key can only
-- be released for a challenge that is TRUSTED, unrevoked, and bound to the
-- requesting device.

CREATE TABLE IF NOT EXISTS examos_exam_key_releases (
    attestation_id varchar(63) PRIMARY KEY
        REFERENCES examos_attestation_challenges (attestation_id) ON DELETE CASCADE,
    session_id varchar(63) NOT NULL
        CHECK (session_id ~ '^[A-Za-z0-9._:-]{1,63}$'),
    device_id varchar(63) NOT NULL
        CHECK (device_id ~ '^[A-Za-z0-9._:-]{1,63}$'),
    release_id varchar(63) NOT NULL
        CHECK (release_id ~ '^[A-Za-z0-9._:-]{1,63}$'),
    key_ciphertext bytea NOT NULL CHECK (octet_length(key_ciphertext) = 32),
    key_nonce bytea NOT NULL CHECK (octet_length(key_nonce) = 12),
    key_tag bytea NOT NULL CHECK (octet_length(key_tag) = 16),
    kek_id varchar(63) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    released_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    consumed_at timestamptz,
    revoked_at timestamptz,
    CHECK (released_at >= created_at)
);

CREATE INDEX IF NOT EXISTS examos_exam_key_release_session_idx
    ON examos_exam_key_releases (session_id, released_at DESC);
CREATE INDEX IF NOT EXISTS examos_exam_key_release_device_idx
    ON examos_exam_key_releases (device_id, released_at DESC);

INSERT INTO examos_schema_migrations (component, version)
VALUES ('exam_key_releases', 1)
ON CONFLICT (component, version) DO NOTHING;

COMMIT;
