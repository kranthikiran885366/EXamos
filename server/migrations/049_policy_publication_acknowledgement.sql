BEGIN;

CREATE TABLE IF NOT EXISTS examos_policy_signing_keys (
    key_id varchar(63) PRIMARY KEY,
    institution_id varchar(63) NOT NULL,
    public_key_pem text NOT NULL,
    public_key_fingerprint char(71) NOT NULL,
    algorithm varchar(31) NOT NULL CHECK (algorithm IN ('ed25519')),
    status varchar(31) NOT NULL CHECK (status IN ('active', 'revoked', 'rotated')),
    valid_from timestamptz NOT NULL,
    valid_until timestamptz,
    rotated_from varchar(63) REFERENCES examos_policy_signing_keys(key_id),
    revoked_at timestamptz,
    revocation_reason text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE IF NOT EXISTS examos_published_policies (
    policy_release_id varchar(63) PRIMARY KEY,
    exam_id varchar(63) NOT NULL,
    institution_id varchar(63) NOT NULL,
    policy_version integer NOT NULL CHECK (policy_version > 0),
    canonical_payload text NOT NULL,
    canonical_payload_sha256 char(71) NOT NULL
        CHECK (canonical_payload_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    canonical_version varchar(31) NOT NULL CHECK (canonical_version IN ('RFC8785')),
    signing_key_id varchar(63) NOT NULL REFERENCES examos_policy_signing_keys(key_id),
    signature_base64 text NOT NULL,
    state varchar(31) NOT NULL CHECK (state IN (
        'PUBLISHED', 'SUPERSEDED', 'REVOKED'
    )),
    published_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    revoked_at timestamptz,
    revocation_reason text NOT NULL DEFAULT '',
    UNIQUE (exam_id, policy_version)
);

CREATE TABLE IF NOT EXISTS examos_policy_enforcement_challenges (
    challenge_id varchar(63) PRIMARY KEY,
    exam_id varchar(63) NOT NULL,
    institution_id varchar(63) NOT NULL,
    device_id varchar(63) NOT NULL,
    policy_release_id varchar(63) NOT NULL
        REFERENCES examos_published_policies(policy_release_id),
    policy_version integer NOT NULL,
    policy_digest char(71) NOT NULL
        CHECK (policy_digest ~ '^sha256:[0-9a-f]{64}$'),
    nonce_sha256 char(64) NOT NULL UNIQUE
        CHECK (nonce_sha256 ~ '^[0-9a-f]{64}$'),
    state varchar(31) NOT NULL CHECK (state IN ('pending', 'used', 'expired', 'revoked')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    used_at timestamptz,
    CHECK (expires_at > created_at)
);

CREATE TABLE IF NOT EXISTS examos_policy_device_acknowledgements (
    acknowledgement_id varchar(63) PRIMARY KEY,
    challenge_id varchar(63) NOT NULL UNIQUE
        REFERENCES examos_policy_enforcement_challenges(challenge_id),
    exam_id varchar(63) NOT NULL,
    institution_id varchar(63) NOT NULL,
    device_id varchar(63) NOT NULL,
    policy_release_id varchar(63) NOT NULL
        REFERENCES examos_published_policies(policy_release_id),
    policy_version integer NOT NULL,
    policy_digest char(71) NOT NULL
        CHECK (policy_digest ~ '^sha256:[0-9a-f]{64}$'),
    enforcement_status varchar(31) NOT NULL CHECK (
        enforcement_status IN ('ENFORCED', 'FAILED')
    ),
    attestation_id varchar(63) NOT NULL,
    signature_base64 text NOT NULL,
    acknowledged_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE UNIQUE INDEX examos_policy_active_release_idx
    ON examos_published_policies(exam_id)
    WHERE state = 'PUBLISHED';

REVOKE INSERT, UPDATE, DELETE ON examos_policy_signing_keys FROM PUBLIC;
REVOKE INSERT, UPDATE, DELETE ON examos_published_policies FROM PUBLIC;
REVOKE INSERT, UPDATE, DELETE ON examos_policy_enforcement_challenges FROM PUBLIC;
REVOKE INSERT, UPDATE, DELETE ON examos_policy_device_acknowledgements FROM PUBLIC;

CREATE OR REPLACE FUNCTION guard_policy_device_acknowledgement()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    challenge_record record;
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'policy acknowledgements are append-only'
            USING ERRCODE = '55000';
    END IF;
    IF TG_OP = 'UPDATE' THEN
        RAISE EXCEPTION 'policy acknowledgements are immutable'
            USING ERRCODE = '55000';
    END IF;

    SELECT c.exam_id,c.institution_id,c.device_id,c.policy_release_id,
           c.policy_version,c.policy_digest,c.state,c.expires_at
    INTO challenge_record
    FROM examos_policy_enforcement_challenges c
    WHERE c.challenge_id=NEW.challenge_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'policy acknowledgement challenge does not exist'
            USING ERRCODE = '55000';
    END IF;
    IF challenge_record.state <> 'pending' OR
       challenge_record.expires_at <= clock_timestamp() THEN
        RAISE EXCEPTION 'policy acknowledgement challenge is stale or consumed'
            USING ERRCODE = '55000';
    END IF;
    IF NEW.exam_id IS DISTINCT FROM challenge_record.exam_id OR
       NEW.institution_id IS DISTINCT FROM challenge_record.institution_id OR
       NEW.device_id IS DISTINCT FROM challenge_record.device_id OR
       NEW.policy_release_id IS DISTINCT FROM challenge_record.policy_release_id OR
       NEW.policy_version IS DISTINCT FROM challenge_record.policy_version OR
       NEW.policy_digest IS DISTINCT FROM challenge_record.policy_digest OR
       NEW.attestation_id='' OR NEW.signature_base64='' THEN
        RAISE EXCEPTION 'policy acknowledgement does not match its challenge'
            USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS examos_policy_ack_guard ON examos_policy_device_acknowledgements;
CREATE TRIGGER examos_policy_ack_guard
    BEFORE INSERT OR UPDATE OR DELETE ON examos_policy_device_acknowledgements
    FOR EACH ROW EXECUTE FUNCTION guard_policy_device_acknowledgement();

INSERT INTO examos_schema_migrations(component, version)
VALUES ('policy_trust', 49)
ON CONFLICT (component, version) DO NOTHING;

COMMIT;
