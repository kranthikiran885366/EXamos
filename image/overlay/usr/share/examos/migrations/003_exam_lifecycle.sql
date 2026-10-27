BEGIN;

-- Migration 003: Dynamic Exam Management (Module C)
-- Covers complete exam lifecycle, institutions, campuses, rooms,
-- rosters, policies, candidate assignments, and audit logging.

CREATE TABLE IF NOT EXISTS examos_institutions (
    institution_id varchar(63) PRIMARY KEY,
    name varchar(127) NOT NULL,
    code varchar(31) NOT NULL UNIQUE,
    domain_email varchar(127) NOT NULL DEFAULT '',
    retention_days integer NOT NULL DEFAULT 365,
    active boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE IF NOT EXISTS examos_campuses (
    campus_id varchar(63) PRIMARY KEY,
    institution_id varchar(63) NOT NULL REFERENCES examos_institutions(institution_id) ON DELETE CASCADE,
    name varchar(127) NOT NULL,
    address text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE IF NOT EXISTS examos_rooms (
    room_id varchar(63) PRIMARY KEY,
    campus_id varchar(63) NOT NULL REFERENCES examos_campuses(campus_id) ON DELETE CASCADE,
    institution_id varchar(63) NOT NULL REFERENCES examos_institutions(institution_id) ON DELETE CASCADE,
    name varchar(127) NOT NULL,
    capacity integer NOT NULL DEFAULT 50 CHECK (capacity > 0),
    supervisor varchar(127) NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE IF NOT EXISTS examos_exams (
    exam_id varchar(63) PRIMARY KEY,
    institution_id varchar(63) NOT NULL REFERENCES examos_institutions(institution_id) ON DELETE RESTRICT,
    owner_user_id varchar(63) REFERENCES examos_admin_users(user_id) ON DELETE SET NULL,
    code varchar(31) NOT NULL,
    title varchar(127) NOT NULL,
    exam_url text NOT NULL,
    allowed_origins text NOT NULL DEFAULT '',
    additional_apis text NOT NULL DEFAULT '',
    duration_minutes integer NOT NULL CHECK (duration_minutes > 0),
    scheduled_start timestamptz NOT NULL,
    scheduled_end timestamptz NOT NULL,
    timezone varchar(63) NOT NULL DEFAULT 'UTC',
    state varchar(31) NOT NULL DEFAULT 'DRAFT' CHECK (state IN (
        'DRAFT', 'VALIDATED', 'APPROVED', 'SCHEDULED', 'OPEN',
        'ACTIVE', 'PAUSED', 'SUBMISSION', 'CLOSED', 'RECONCILED'
    )),
    approved_by varchar(63) REFERENCES examos_admin_users(user_id) ON DELETE SET NULL,
    approved_at timestamptz,
    policy_version integer NOT NULL DEFAULT 1,
    policy_signature varchar(64) NOT NULL DEFAULT '',
    permitted_device_group varchar(63) NOT NULL DEFAULT 'ALL',
    accommodations_allowed boolean NOT NULL DEFAULT true,
    network_offline_allowed boolean NOT NULL DEFAULT false,
    browser_policy_json text NOT NULL DEFAULT '{}',
    incident_appeal_procedure text NOT NULL DEFAULT '',
    retention_days integer NOT NULL DEFAULT 365,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK (scheduled_end > scheduled_start)
);
CREATE INDEX IF NOT EXISTS examos_exams_inst_idx ON examos_exams (institution_id);
CREATE INDEX IF NOT EXISTS examos_exams_state_idx ON examos_exams (state);

CREATE TABLE IF NOT EXISTS examos_exam_policies (
    policy_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    exam_id varchar(63) NOT NULL REFERENCES examos_exams(exam_id) ON DELETE CASCADE,
    policy_version integer NOT NULL,
    exam_url text NOT NULL,
    allowed_origins text NOT NULL DEFAULT '',
    permitted_apps text NOT NULL DEFAULT '',
    signature varchar(64) NOT NULL,
    approved_by varchar(63) REFERENCES examos_admin_users(user_id) ON DELETE SET NULL,
    status varchar(31) NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'SUPERSEDED', 'ROLLBACK')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (exam_id, policy_version)
);

CREATE TABLE IF NOT EXISTS examos_exam_roster (
    roster_id varchar(63) PRIMARY KEY,
    exam_id varchar(63) NOT NULL REFERENCES examos_exams(exam_id) ON DELETE CASCADE,
    candidate_id varchar(63) NOT NULL,
    full_name varchar(127) NOT NULL,
    email varchar(127) NOT NULL,
    pin_hash varchar(127) NOT NULL,
    room_id varchar(63) REFERENCES examos_rooms(room_id) ON DELETE SET NULL,
    assigned_seat varchar(31) NOT NULL DEFAULT '',
    assigned_device_id varchar(63) NOT NULL DEFAULT '',
    status varchar(31) NOT NULL DEFAULT 'ELIGIBLE' CHECK (status IN (
        'ELIGIBLE', 'CHECKED_IN', 'IN_EXAM', 'SUBMITTED', 'DISQUALIFIED'
    )),
    accommodation_extra_time_mins integer NOT NULL DEFAULT 0,
    check_in_time timestamptz,
    submit_time timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (exam_id, candidate_id)
);
CREATE INDEX IF NOT EXISTS examos_exam_roster_exam_status_idx ON examos_exam_roster (exam_id, status);

CREATE TABLE IF NOT EXISTS examos_exam_readiness_checks (
    check_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    exam_id varchar(63) NOT NULL REFERENCES examos_exams(exam_id) ON DELETE CASCADE,
    device_id varchar(63) NOT NULL,
    network_ok boolean NOT NULL DEFAULT false,
    tpm_attested boolean NOT NULL DEFAULT false,
    kiosk_policy_ready boolean NOT NULL DEFAULT false,
    camera_ready boolean NOT NULL DEFAULT false,
    passed boolean NOT NULL DEFAULT false,
    details text NOT NULL DEFAULT '',
    checked_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

-- Expand audit event types to cover the complete exam lifecycle
ALTER TABLE examos_admin_audit
    DROP CONSTRAINT IF EXISTS examos_admin_audit_event_type_check;

ALTER TABLE examos_admin_audit
    ADD CONSTRAINT examos_admin_audit_event_type_check
    CHECK (event_type IN (
        'ADMIN_SESSION_CREATED',
        'ADMIN_SESSION_REVOKED',
        'ADMIN_LOGIN_FAILED',
        'ADMIN_MFA_ENROLLED',
        'ADMIN_MFA_VERIFIED',
        'ADMIN_MFA_FAILED',
        'ADMIN_RECOVERY_USED',
        'ADMIN_PASSWORD_RESET_REQUESTED',
        'ADMIN_PASSWORD_RESET_COMPLETED',
        'ADMIN_USER_CREATED',
        'ADMIN_USER_UPDATED',
        'EXAM_DRAFT_CREATED',
        'EXAM_CONFIG_VALIDATED',
        'EXAM_APPROVED',
        'EXAM_SCHEDULED',
        'EXAM_OPENED',
        'EXAM_ACTIVATED',
        'EXAM_PAUSED',
        'EXAM_SUBMISSION_WINDOW',
        'EXAM_CLOSED',
        'EXAM_RECONCILED',
        'EXAM_PURGED_RETENTION',
        'EXAM_ROSTER_CANDIDATE_ADDED',
        'EXAM_CANDIDATE_ASSIGNED',
        'EXAM_READINESS_CHECKED',
        'EXAM_POLICY_PUBLISHED',
        'EXAM_POLICY_ROLLBACK'
    ));

INSERT INTO examos_schema_migrations (component, version)
VALUES ('exam_lifecycle', 3);

COMMIT;
