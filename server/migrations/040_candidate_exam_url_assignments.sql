-- ============================================================================
-- Migration 040: Candidate Individual Exam URL Assignments & Audit
-- Enhances exam_student_assignments with candidate-specific URL assignment,
-- scheduling constraints, credential references, revocation metadata,
-- and dedicated assignment audit trail.
-- ============================================================================

BEGIN;

-- 1. Extend exam_student_assignments with individual exam URL and lifecycle fields
ALTER TABLE exam_student_assignments
    ADD COLUMN IF NOT EXISTS assigned_exam_url TEXT DEFAULT '',
    ADD COLUMN IF NOT EXISTS exam_date VARCHAR(32) DEFAULT '',
    ADD COLUMN IF NOT EXISTS start_time BIGINT DEFAULT 0,
    ADD COLUMN IF NOT EXISTS end_time BIGINT DEFAULT 0,
    ADD COLUMN IF NOT EXISTS timezone VARCHAR(64) DEFAULT 'UTC',
    ADD COLUMN IF NOT EXISTS assignment_status VARCHAR(32) DEFAULT 'active',
    ADD COLUMN IF NOT EXISTS credential_ref VARCHAR(64) DEFAULT '',
    ADD COLUMN IF NOT EXISTS device_policy VARCHAR(64) DEFAULT '',
    ADD COLUMN IF NOT EXISTS created_by VARCHAR(64) DEFAULT '',
    ADD COLUMN IF NOT EXISTS approval_state VARCHAR(32) DEFAULT 'approved',
    ADD COLUMN IF NOT EXISTS approved_by VARCHAR(64) DEFAULT '',
    ADD COLUMN IF NOT EXISTS revoked_at BIGINT,
    ADD COLUMN IF NOT EXISTS revoked_by VARCHAR(64) DEFAULT '',
    ADD COLUMN IF NOT EXISTS revocation_reason TEXT DEFAULT '';

-- Validate assignment_status values
ALTER TABLE exam_student_assignments
    DROP CONSTRAINT IF EXISTS chk_exam_student_assignment_status;
ALTER TABLE exam_student_assignments
    ADD CONSTRAINT chk_exam_student_assignment_status
    CHECK (assignment_status IN ('active', 'pending_approval', 'suspended', 'revoked', 'completed'));

-- Validate approval_state values
ALTER TABLE exam_student_assignments
    DROP CONSTRAINT IF EXISTS chk_exam_student_approval_state;
ALTER TABLE exam_student_assignments
    ADD CONSTRAINT chk_exam_student_approval_state
    CHECK (approval_state IN ('pending', 'approved', 'rejected'));

-- Unique index to prevent duplicate active assignments for the same candidate and examination
CREATE UNIQUE INDEX IF NOT EXISTS uq_active_candidate_exam_assignment
    ON exam_student_assignments(exam_id, student_id)
    WHERE assignment_status = 'active';

CREATE INDEX IF NOT EXISTS idx_exam_student_assignments_status
    ON exam_student_assignments(assignment_status, exam_id);

CREATE INDEX IF NOT EXISTS idx_exam_student_assignments_candidate
    ON exam_student_assignments(student_id, assignment_status);

-- 2. Audit Trail for URL Assignments and Modifications
CREATE TABLE IF NOT EXISTS candidate_exam_assignment_audit (
    id VARCHAR(64) PRIMARY KEY,
    assignment_id VARCHAR(64) NOT NULL REFERENCES exam_student_assignments(id) ON DELETE CASCADE,
    exam_id VARCHAR(64) NOT NULL REFERENCES examinations(id) ON DELETE CASCADE,
    student_id VARCHAR(64) NOT NULL,
    institution_id VARCHAR(64) NOT NULL,
    action VARCHAR(32) NOT NULL CHECK (action IN ('created', 'url_updated', 'status_changed', 'approved', 'revoked')),
    previous_url TEXT DEFAULT '',
    new_url TEXT DEFAULT '',
    previous_status VARCHAR(32) DEFAULT '',
    new_status VARCHAR(32) DEFAULT '',
    performed_by VARCHAR(64) NOT NULL,
    reason TEXT DEFAULT '',
    timestamp BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_assignment_audit_assignment
    ON candidate_exam_assignment_audit(assignment_id, timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_assignment_audit_exam
    ON candidate_exam_assignment_audit(exam_id, student_id);

INSERT INTO examos_schema_migrations(component, version)
VALUES ('candidate_exam_url_assignments', 1)
ON CONFLICT (component, version) DO NOTHING;

COMMIT;
