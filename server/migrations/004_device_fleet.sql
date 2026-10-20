BEGIN;

-- Migration 004: Device Enrollment and Fleet Management (Module G)
-- Enterprise schema for stable device identity, multi-campus grouping,
-- cryptographic attestation references, compliance, bulk actions, and audit logging.

CREATE TABLE IF NOT EXISTS examos_devices (
    device_id varchar(63) PRIMARY KEY,
    hostname varchar(63) NOT NULL,
    institution_id varchar(63) REFERENCES examos_institutions(institution_id) ON DELETE SET NULL,
    campus_id varchar(63) REFERENCES examos_campuses(campus_id) ON DELETE SET NULL,
    room_id varchar(63) REFERENCES examos_rooms(room_id) ON DELETE SET NULL,
    group_name varchar(63) NOT NULL DEFAULT 'DEFAULT',
    deployment_ring varchar(31) NOT NULL DEFAULT 'PILOT' CHECK (deployment_ring IN ('CANARY', 'PILOT', 'GENERAL')),
    ownership_type varchar(31) NOT NULL DEFAULT 'INSTITUTION_OWNED' CHECK (ownership_type IN ('INSTITUTION_OWNED', 'STUDENT_OWNED')),
    student_owned boolean NOT NULL DEFAULT false,
    hardware_platform varchar(127) NOT NULL DEFAULT 'x86_64 / UEFI TPM 2.0',
    enrollment_status varchar(31) NOT NULL DEFAULT 'PENDING_APPROVAL' CHECK (enrollment_status IN (
        'PENDING_APPROVAL', 'ENROLLED', 'REJECTED', 'REVOKED', 'UNENROLLED', 'QUARANTINED', 'REPLACED'
    )),
    crypto_identity_ref varchar(127) NOT NULL DEFAULT '',
    os_release varchar(63) NOT NULL DEFAULT 'examos-2.0.26',
    image_digest varchar(64) NOT NULL DEFAULT '',
    uki_digest varchar(64) NOT NULL DEFAULT '',
    policy_version integer NOT NULL DEFAULT 1,
    attestation_status varchar(31) NOT NULL DEFAULT 'NOT_ATTESTED' CHECK (attestation_status IN (
        'TRUSTED', 'FAILED', 'STALE', 'NOT_ATTESTED'
    )),
    last_attestation_ts timestamptz,
    compliance_status varchar(31) NOT NULL DEFAULT 'COMPLIANT' CHECK (compliance_status IN (
        'COMPLIANT', 'NON_COMPLIANT', 'MAINTENANCE', 'QUARANTINED'
    )),
    assigned_exam_id varchar(63) REFERENCES examos_exams(exam_id) ON DELETE SET NULL,
    current_candidate_id varchar(63) NOT NULL DEFAULT '',
    session_state varchar(31) NOT NULL DEFAULT 'IDLE' CHECK (session_state IN (
        'IDLE', 'CHECKED_IN', 'IN_EXAM', 'SUBMITTED'
    )),
    update_status varchar(31) NOT NULL DEFAULT 'UP_TO_DATE' CHECK (update_status IN (
        'UP_TO_DATE', 'UPDATE_PENDING', 'UPDATING', 'UPDATE_FAILED'
    )),
    incident_refs text NOT NULL DEFAULT '',
    replacement_for_device_id varchar(63) DEFAULT NULL,
    maintenance_mode boolean NOT NULL DEFAULT false,
    enrolled boolean NOT NULL DEFAULT false,
    last_checkin timestamptz NOT NULL DEFAULT clock_timestamp(),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX IF NOT EXISTS examos_devices_inst_idx ON examos_devices (institution_id);
CREATE INDEX IF NOT EXISTS examos_devices_group_idx ON examos_devices (group_name);
CREATE INDEX IF NOT EXISTS examos_devices_status_idx ON examos_devices (enrollment_status, compliance_status);

CREATE TABLE IF NOT EXISTS examos_device_heartbeats (
    heartbeat_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    device_id varchar(63) NOT NULL REFERENCES examos_devices(device_id) ON DELETE CASCADE,
    battery_pct integer DEFAULT -1,
    battery_charging boolean DEFAULT false,
    disk_free_mb integer DEFAULT 0,
    mem_used_mb integer DEFAULT 0,
    network_state varchar(31) NOT NULL DEFAULT 'CONNECTED',
    policy_version integer NOT NULL DEFAULT 1,
    image_digest varchar(64) NOT NULL DEFAULT '',
    session_state varchar(31) NOT NULL DEFAULT 'IDLE',
    reported_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX IF NOT EXISTS examos_device_hb_dev_idx ON examos_device_heartbeats (device_id, reported_at DESC);

CREATE TABLE IF NOT EXISTS examos_device_bulk_jobs (
    job_id varchar(63) PRIMARY KEY,
    actor_user_id varchar(63) REFERENCES examos_admin_users(user_id) ON DELETE SET NULL,
    action_type varchar(31) NOT NULL,
    target_filter text NOT NULL DEFAULT '{}',
    total_targeted integer NOT NULL DEFAULT 0,
    succeeded integer NOT NULL DEFAULT 0,
    failed integer NOT NULL DEFAULT 0,
    status varchar(31) NOT NULL DEFAULT 'COMPLETED',
    details text NOT NULL DEFAULT '{}',
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

-- Expand audit event types to cover Module G fleet actions
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
        'EXAM_POLICY_ROLLBACK',
        'DEVICE_ENROLLED',
        'DEVICE_ENROLLMENT_APPROVED',
        'DEVICE_ENROLLMENT_REJECTED',
        'DEVICE_ENROLLMENT_REVOKED',
        'DEVICE_HEARTBEAT',
        'DEVICE_MAINTENANCE_TOGGLED',
        'DEVICE_QUARANTINED',
        'DEVICE_CREDENTIALS_REVOKED',
        'DEVICE_UNENROLLED',
        'DEVICE_REPLACED',
        'DEVICE_BULK_ACTION'
    ));

INSERT INTO examos_schema_migrations (component, version)
VALUES ('device_fleet', 4);

COMMIT;
