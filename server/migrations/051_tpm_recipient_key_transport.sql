BEGIN;

CREATE TABLE IF NOT EXISTS examos_exam_key_transports (
    transport_id varchar(63) PRIMARY KEY,
    attestation_id varchar(63) NOT NULL
        REFERENCES examos_attestation_challenges(attestation_id) ON DELETE CASCADE,
    session_id varchar(63) NOT NULL,
    candidate_id varchar(63) NOT NULL,
    device_id varchar(63) NOT NULL,
    recipient_fingerprint char(64) NOT NULL,
    algorithm varchar(31) NOT NULL CHECK (algorithm IN ('rsa-oaep-sha256')),
    envelope_sha256 char(71) NOT NULL
        CHECK (envelope_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    envelope_base64 text NOT NULL,
    state varchar(31) NOT NULL CHECK (state IN ('wrapped', 'consumed', 'revoked')),
    wrapped_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    consumed_at timestamptz,
    revoked_at timestamptz,
    CHECK ((state='consumed') = (consumed_at IS NOT NULL)),
    CHECK ((state='revoked') = (revoked_at IS NOT NULL))
);

CREATE UNIQUE INDEX examos_exam_key_transport_one_active
    ON examos_exam_key_transports(session_id, device_id)
    WHERE state='wrapped';
CREATE INDEX examos_exam_key_transport_candidate_idx
    ON examos_exam_key_transports(candidate_id, wrapped_at DESC);

REVOKE INSERT, UPDATE, DELETE ON examos_exam_key_transports FROM PUBLIC;

CREATE OR REPLACE FUNCTION guard_exam_key_transport_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='DELETE' THEN
        RAISE EXCEPTION 'exam key transport evidence is append-only'
            USING ERRCODE='55000';
    END IF;
    IF TG_OP='UPDATE' AND NEW.transport_id IS DISTINCT FROM OLD.transport_id THEN
        RAISE EXCEPTION 'exam key transport evidence is immutable'
            USING ERRCODE='55000';
    END IF;
    IF TG_OP='UPDATE' AND OLD.state='consumed' THEN
        RAISE EXCEPTION 'consumed exam key transports cannot be reused'
            USING ERRCODE='55000';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS examos_exam_key_transport_append_only
    ON examos_exam_key_transports;
CREATE TRIGGER examos_exam_key_transport_append_only
    BEFORE UPDATE OR DELETE ON examos_exam_key_transports
    FOR EACH ROW EXECUTE FUNCTION guard_exam_key_transport_mutation();

INSERT INTO examos_schema_migrations(component, version)
VALUES ('exam_key_transport', 51)
ON CONFLICT (component, version) DO NOTHING;

COMMIT;
