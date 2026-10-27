BEGIN;

-- Migration 013: Session journal, audit event completions, exam_policies alignment

CREATE TABLE IF NOT EXISTS examos_candidate_sessions (
    token_hash char(64) PRIMARY KEY CHECK (token_hash ~ '^[0-9a-f]{64}$'),
    candidate_id varchar(63) NOT NULL CHECK (candidate_id ~ '^[A-Za-z0-9._@+-]{1,63}$'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    invalidated_at timestamptz,
    CHECK (expires_at > created_at)
);
CREATE INDEX IF NOT EXISTS examos_candidate_sessions_cid_idx
    ON examos_candidate_sessions (candidate_id, expires_at)
    WHERE invalidated_at IS NULL;

-- Align exam_policies: add allowed_origins if missing (003 used permitted_apps)
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'examos_exam_policies'
          AND column_name = 'allowed_origins'
    ) THEN
        ALTER TABLE examos_exam_policies
            ADD COLUMN allowed_origins text NOT NULL DEFAULT '';
    END IF;
END$$;

-- Complete audit event type constraint covering all implemented events
ALTER TABLE examos_admin_audit
    DROP CONSTRAINT IF EXISTS examos_admin_audit_event_type_check;

ALTER TABLE examos_admin_audit
    ADD CONSTRAINT examos_admin_audit_event_type_check
    CHECK (event_type IN (
        'ADMIN_SESSION_CREATED','ADMIN_SESSION_REVOKED','ADMIN_LOGIN_FAILED',
        'ADMIN_MFA_ENROLLED','ADMIN_MFA_VERIFIED','ADMIN_MFA_FAILED',
        'ADMIN_RECOVERY_USED','ADMIN_PASSWORD_RESET_REQUESTED',
        'ADMIN_PASSWORD_RESET_COMPLETED','ADMIN_USER_CREATED','ADMIN_USER_UPDATED',
        'ADMIN_CANDIDATE_ROSTER_READ','ADMIN_CONFIG_UPDATED',
        'EXAM_DRAFT_CREATED','EXAM_CONFIG_VALIDATED','EXAM_APPROVED',
        'EXAM_SCHEDULED','EXAM_OPENED','EXAM_ACTIVATED','EXAM_PAUSED',
        'EXAM_SUBMISSION_WINDOW','EXAM_CLOSED','EXAM_RECONCILED',
        'EXAM_PURGED_RETENTION','EXAM_ROSTER_CANDIDATE_ADDED',
        'EXAM_CANDIDATE_ASSIGNED','EXAM_READINESS_CHECKED',
        'EXAM_POLICY_PUBLISHED','EXAM_POLICY_ROLLBACK',
        'DEVICE_ENROLLED','DEVICE_ENROLLMENT_APPROVED','DEVICE_ENROLLMENT_REJECTED',
        'DEVICE_ENROLLMENT_REVOKED','DEVICE_HEARTBEAT','DEVICE_MAINTENANCE_TOGGLED',
        'DEVICE_QUARANTINED','DEVICE_CREDENTIALS_REVOKED','DEVICE_UNENROLLED',
        'DEVICE_REPLACED','DEVICE_BULK_ACTION',
        'INCIDENT_RAISED','INCIDENT_STATUS'
    ));

INSERT INTO examos_schema_migrations (component, version)
VALUES ('admin_auth', 8)
ON CONFLICT (component, version) DO NOTHING;

COMMIT;
