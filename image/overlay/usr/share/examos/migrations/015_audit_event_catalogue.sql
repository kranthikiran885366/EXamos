BEGIN;

-- Migration 015: complete the administrative audit event catalogue and
-- make the audit trail readable by the administration dashboard.
--
-- The audit event_type constraint only listed part of the event vocabulary
-- that the platform actually produces. A lifecycle transition such as
-- DRAFT -> VALIDATED was therefore recorded in the evidence ledger but
-- silently dropped from the administrative audit trail, because the audit
-- insert violated this constraint.

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
        'INSTITUTION_CREATED','INSTITUTION_UPDATED',
        'EXAM_DRAFT_CREATED','EXAM_DRAFT','EXAM_CONFIG_VALIDATED','EXAM_VALIDATED',
        'EXAM_APPROVED','EXAM_SCHEDULED','EXAM_OPENED','EXAM_ACTIVATED','EXAM_PAUSED',
        'EXAM_SUBMISSION_WINDOW','EXAM_CLOSED','EXAM_RECONCILED','EXAM_STATE_CHANGED',
        'EXAM_PURGED_RETENTION','EXAM_ROSTER_CANDIDATE_ADDED',
        'EXAM_CANDIDATE_ASSIGNED','EXAM_CANDIDATE_CHECKED_IN',
        'EXAM_SUBMISSION_RECORDED','EXAM_READINESS_CHECKED',
        'EXAM_POLICY_PUBLISHED','EXAM_POLICY_ROLLBACK','POLICY_DISTRIBUTED',
        'DEVICE_ENROLLED','DEVICE_ENROLLMENT_APPROVED','DEVICE_ENROLLMENT_REJECTED',
        'DEVICE_ENROLLMENT_REVOKED','DEVICE_HEARTBEAT','DEVICE_MAINTENANCE_TOGGLED',
        'DEVICE_QUARANTINED','DEVICE_CREDENTIALS_REVOKED','DEVICE_UNENROLLED',
        'DEVICE_REPLACED','DEVICE_BULK_ACTION','DEVICE_ASSIGNED_TO_EXAM',
        'RELEASE_CREATED',
        'INCIDENT_RAISED','INCIDENT_STATUS'
    ));

-- The audit trail carries the identity of the actor and the event, but not
-- the entity the event was about. The administration dashboard needs to
-- show which exam, device or incident an event refers to, so the subject is
-- recorded alongside the event.
ALTER TABLE examos_admin_audit
    ADD COLUMN IF NOT EXISTS subject_type varchar(31) NOT NULL DEFAULT '';

ALTER TABLE examos_admin_audit
    ADD COLUMN IF NOT EXISTS subject_id varchar(63) NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS examos_admin_audit_subject_idx
    ON examos_admin_audit (subject_type, subject_id, occurred_at DESC);

INSERT INTO examos_schema_migrations (component, version)
VALUES ('admin_auth', 9)
ON CONFLICT (component, version) DO NOTHING;

COMMIT;
