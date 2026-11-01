-- ============================================================================
-- Migration 020: Examination Registration & Eligibility Management (Module 10)
-- Student profiles, configurable eligibility rules, evaluations, approvals,
-- exceptions, bulk import jobs, versioned roster publications, and audit logs.
-- ============================================================================

BEGIN;

-- 1. Student Master Management table
CREATE TABLE IF NOT EXISTS students (
    id VARCHAR(64) PRIMARY KEY,
    institution_id VARCHAR(64) NOT NULL,
    roll_no VARCHAR(64) NOT NULL,
    name VARCHAR(128) NOT NULL,
    email VARCHAR(128) NOT NULL DEFAULT '',
    course VARCHAR(128) NOT NULL DEFAULT '',
    department_id VARCHAR(64),
    campus_id VARCHAR(64),
    semester INTEGER NOT NULL DEFAULT 1,
    academic_status VARCHAR(32) NOT NULL DEFAULT 'active' CHECK (academic_status IN (
        'active', 'suspended', 'probation', 'withdrawn', 'graduated'
    )),
    attendance_pct INTEGER NOT NULL DEFAULT 100 CHECK (attendance_pct >= 0 AND attendance_pct <= 100),
    prerequisites_completed TEXT NOT NULL DEFAULT '',
    administrative_hold BOOLEAN NOT NULL DEFAULT false,
    hold_reason TEXT DEFAULT '',
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    CONSTRAINT uq_institution_student_roll UNIQUE (institution_id, roll_no)
);

CREATE INDEX IF NOT EXISTS idx_students_institution ON students (institution_id);
CREATE INDEX IF NOT EXISTS idx_students_roll_no ON students (roll_no);

-- 2. Configurable Eligibility Rules table
CREATE TABLE IF NOT EXISTS eligibility_rules (
    id VARCHAR(64) PRIMARY KEY,
    institution_id VARCHAR(64) NOT NULL,
    examination_id VARCHAR(64) NOT NULL REFERENCES examinations(id) ON DELETE CASCADE,
    rule_type VARCHAR(32) NOT NULL CHECK (rule_type IN (
        'course_enrollment', 'semester', 'academic_status', 'registration_deadline',
        'prerequisites', 'attendance', 'administrative_hold'
    )),
    rule_config_json TEXT NOT NULL DEFAULT '{}',
    version INTEGER NOT NULL DEFAULT 1,
    active BOOLEAN NOT NULL DEFAULT true,
    created_at BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_eligibility_rules_exam ON eligibility_rules (examination_id);
CREATE INDEX IF NOT EXISTS idx_eligibility_rules_inst ON eligibility_rules (institution_id);

-- 3. Exam Registrations table
CREATE TABLE IF NOT EXISTS exam_registrations (
    id VARCHAR(64) PRIMARY KEY,
    institution_id VARCHAR(64) NOT NULL,
    examination_id VARCHAR(64) NOT NULL REFERENCES examinations(id) ON DELETE CASCADE,
    student_id VARCHAR(64) NOT NULL,
    registration_status VARCHAR(32) NOT NULL DEFAULT 'submitted' CHECK (registration_status IN (
        'submitted', 'pending_validation', 'approved', 'rejected', 'exception_review', 'roster_published'
    )),
    eligibility_status VARCHAR(32) NOT NULL DEFAULT 'pending' CHECK (eligibility_status IN (
        'pending', 'eligible', 'ineligible', 'exempted'
    )),
    submitted_at BIGINT NOT NULL,
    evaluated_at BIGINT,
    approved_by VARCHAR(64),
    approved_at BIGINT,
    rejection_reason TEXT,
    exception_reason TEXT,
    exception_by VARCHAR(64),
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    CONSTRAINT uq_exam_student_registration UNIQUE (institution_id, examination_id, student_id)
);

CREATE INDEX IF NOT EXISTS idx_exam_registrations_exam ON exam_registrations (examination_id);
CREATE INDEX IF NOT EXISTS idx_exam_registrations_student ON exam_registrations (student_id);
CREATE INDEX IF NOT EXISTS idx_exam_registrations_status ON exam_registrations (registration_status);

-- 4. Eligibility Evaluations audit trail
CREATE TABLE IF NOT EXISTS eligibility_evaluations (
    id VARCHAR(64) PRIMARY KEY,
    registration_id VARCHAR(64) NOT NULL REFERENCES exam_registrations(id) ON DELETE CASCADE,
    examination_id VARCHAR(64) NOT NULL,
    student_id VARCHAR(64) NOT NULL,
    passed BOOLEAN NOT NULL,
    details_json TEXT NOT NULL DEFAULT '{}',
    evaluated_by VARCHAR(64) NOT NULL DEFAULT 'system',
    evaluated_at BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_eligibility_evals_reg ON eligibility_evaluations (registration_id);

-- 5. Registration Approvals & Exceptions decisions
CREATE TABLE IF NOT EXISTS registration_approvals (
    id VARCHAR(64) PRIMARY KEY,
    registration_id VARCHAR(64) NOT NULL REFERENCES exam_registrations(id) ON DELETE CASCADE,
    decision VARCHAR(32) NOT NULL CHECK (decision IN ('approved', 'rejected', 'exception_approved')),
    decided_by VARCHAR(64) NOT NULL,
    reason TEXT,
    created_at BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_registration_approvals_reg ON registration_approvals (registration_id);

-- 6. Bulk Import Jobs
CREATE TABLE IF NOT EXISTS registration_import_jobs (
    id VARCHAR(64) PRIMARY KEY,
    examination_id VARCHAR(64) NOT NULL REFERENCES examinations(id) ON DELETE CASCADE,
    institution_id VARCHAR(64) NOT NULL,
    total_rows INTEGER NOT NULL DEFAULT 0,
    valid_rows INTEGER NOT NULL DEFAULT 0,
    error_rows INTEGER NOT NULL DEFAULT 0,
    status VARCHAR(32) NOT NULL DEFAULT 'processing' CHECK (status IN ('processing', 'completed', 'failed')),
    created_by VARCHAR(64) NOT NULL,
    created_at BIGINT NOT NULL,
    completed_at BIGINT
);

CREATE INDEX IF NOT EXISTS idx_reg_import_jobs_exam ON registration_import_jobs (examination_id);

-- 7. Bulk Import Errors Breakdown
CREATE TABLE IF NOT EXISTS registration_import_errors (
    id VARCHAR(64) PRIMARY KEY,
    job_id VARCHAR(64) NOT NULL REFERENCES registration_import_jobs(id) ON DELETE CASCADE,
    row_index INTEGER NOT NULL,
    student_id VARCHAR(64),
    error_code VARCHAR(64) NOT NULL,
    error_message TEXT NOT NULL,
    created_at BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_reg_import_errors_job ON registration_import_errors (job_id);

-- 8. Exam Roster Versions (Immutable snapshots)
CREATE TABLE IF NOT EXISTS exam_roster_versions (
    id VARCHAR(64) PRIMARY KEY,
    examination_id VARCHAR(64) NOT NULL REFERENCES examinations(id) ON DELETE CASCADE,
    institution_id VARCHAR(64) NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    published_by VARCHAR(64) NOT NULL,
    total_students INTEGER NOT NULL DEFAULT 0,
    roster_hash VARCHAR(64) NOT NULL DEFAULT '',
    published_at BIGINT NOT NULL,
    CONSTRAINT uq_exam_roster_version UNIQUE (examination_id, version)
);

CREATE INDEX IF NOT EXISTS idx_roster_versions_exam ON exam_roster_versions (examination_id);

-- 9. Exam Roster Entries
CREATE TABLE IF NOT EXISTS exam_roster_entries (
    id VARCHAR(64) PRIMARY KEY,
    roster_version_id VARCHAR(64) NOT NULL REFERENCES exam_roster_versions(id) ON DELETE CASCADE,
    examination_id VARCHAR(64) NOT NULL,
    student_id VARCHAR(64) NOT NULL,
    roll_no VARCHAR(64) NOT NULL,
    name VARCHAR(128) NOT NULL,
    campus_id VARCHAR(64),
    department_id VARCHAR(64),
    seat_no VARCHAR(32) DEFAULT '',
    created_at BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_roster_entries_version ON exam_roster_entries (roster_version_id);
CREATE INDEX IF NOT EXISTS idx_roster_entries_student ON exam_roster_entries (examination_id, student_id);

-- 10. Registration Audit Logs
CREATE TABLE IF NOT EXISTS registration_audit_logs (
    id VARCHAR(64) PRIMARY KEY,
    registration_id VARCHAR(64),
    examination_id VARCHAR(64) NOT NULL,
    institution_id VARCHAR(64) NOT NULL,
    actor_id VARCHAR(64) NOT NULL,
    action VARCHAR(64) NOT NULL,
    details TEXT DEFAULT '',
    created_at BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_reg_audit_logs_exam ON registration_audit_logs (examination_id);

INSERT INTO examos_schema_migrations (component, version)
VALUES ('examination_registration', 20)
ON CONFLICT (component, version) DO NOTHING;

COMMIT;
