BEGIN;

CREATE TABLE IF NOT EXISTS examos_security_incidents (
    incident_id varchar(63) PRIMARY KEY,
    institution_id varchar(63) REFERENCES examos_institutions(institution_id) ON DELETE SET NULL,
    title varchar(127) NOT NULL,
    severity varchar(15) NOT NULL CHECK (severity IN ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    status varchar(31) NOT NULL CHECK (status IN ('OPEN', 'INVESTIGATING', 'CONTAINED', 'RESOLVED')),
    assigned_to varchar(63) NOT NULL DEFAULT '',
    device_id varchar(63) NOT NULL DEFAULT '',
    candidate_id varchar(63) NOT NULL DEFAULT '',
    exam_id varchar(63) REFERENCES examos_exams(exam_id) ON DELETE SET NULL,
    summary text NOT NULL DEFAULT '',
    resolution_notes text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX IF NOT EXISTS examos_incidents_institution_created_idx
    ON examos_security_incidents (institution_id, created_at DESC);
CREATE INDEX IF NOT EXISTS examos_incidents_status_created_idx
    ON examos_security_incidents (status, created_at DESC);

CREATE TABLE IF NOT EXISTS examos_incident_history (
    history_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    incident_id varchar(63) NOT NULL REFERENCES examos_security_incidents(incident_id) ON DELETE CASCADE,
    actor_user_id varchar(63) REFERENCES examos_admin_users(user_id) ON DELETE SET NULL,
    action varchar(31) NOT NULL CHECK (action IN ('CREATED', 'STATUS_CHANGED')),
    prior_status varchar(31),
    new_status varchar(31) NOT NULL,
    notes text NOT NULL DEFAULT '',
    occurred_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX IF NOT EXISTS examos_incident_history_incident_idx
    ON examos_incident_history (incident_id, occurred_at ASC);

CREATE TABLE IF NOT EXISTS examos_software_releases (
    release_id varchar(63) PRIMARY KEY,
    version_name varchar(63) NOT NULL,
    image_digest varchar(64) NOT NULL CHECK (image_digest ~ '^[0-9a-f]{64}$'),
    uki_digest varchar(64) NOT NULL CHECK (uki_digest ~ '^[0-9a-f]{64}$'),
    sbom_digest varchar(64) NOT NULL CHECK (sbom_digest ~ '^[0-9a-f]{64}$'),
    target_ring varchar(15) NOT NULL CHECK (target_ring IN ('CANARY', 'PILOT', 'GENERAL')),
    status varchar(31) NOT NULL CHECK (status IN ('DRAFT', 'PUBLISHED', 'ROLLED_BACK', 'REVOKED')),
    signed_by varchar(63) NOT NULL DEFAULT '',
    release_date timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX IF NOT EXISTS examos_releases_ring_status_idx
    ON examos_software_releases (target_ring, status, release_date DESC);

INSERT INTO examos_schema_migrations (component, version)
VALUES ('operations', 1);

COMMIT;
