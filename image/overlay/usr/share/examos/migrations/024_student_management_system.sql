-- 024_student_management_system.sql
-- Module 5: Student Management System (Complete Specification)
-- Canonical student profiles, multi-semester enrollment history, identity verification,
-- correction requests, bulk import lifecycle, and durable audit trail.

-- 1. Extend canonical students table with enterprise profile fields
ALTER TABLE students ADD COLUMN IF NOT EXISTS display_name VARCHAR(128) DEFAULT '';
ALTER TABLE students ADD COLUMN IF NOT EXISTS batch VARCHAR(64) DEFAULT '2026';
ALTER TABLE students ADD COLUMN IF NOT EXISTS section VARCHAR(32) DEFAULT 'A';
ALTER TABLE students ADD COLUMN IF NOT EXISTS personal_email VARCHAR(128) DEFAULT '';
ALTER TABLE students ADD COLUMN IF NOT EXISTS phone_number VARCHAR(32) DEFAULT '';
ALTER TABLE students ADD COLUMN IF NOT EXISTS verification_status VARCHAR(32) DEFAULT 'VERIFIED';
ALTER TABLE students ADD COLUMN IF NOT EXISTS record_source VARCHAR(32) DEFAULT 'manual';
ALTER TABLE students ADD COLUMN IF NOT EXISTS account_id VARCHAR(64) DEFAULT '';
ALTER TABLE students ADD COLUMN IF NOT EXISTS accommodations TEXT DEFAULT '';
ALTER TABLE students ADD COLUMN IF NOT EXISTS notes TEXT DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_students_verification ON students(verification_status);
CREATE INDEX IF NOT EXISTS idx_students_dept ON students(department_id);
CREATE INDEX IF NOT EXISTS idx_students_campus ON students(campus_id);

-- 2. Multi-Semester Academic Enrollment History
CREATE TABLE IF NOT EXISTS student_enrollments (
    id VARCHAR(64) PRIMARY KEY,
    student_id VARCHAR(64) NOT NULL REFERENCES students(id) ON DELETE CASCADE,
    institution_id VARCHAR(64) NOT NULL REFERENCES tenants(id),
    campus_id VARCHAR(64) DEFAULT '',
    department_id VARCHAR(64) DEFAULT '',
    program_id VARCHAR(128) DEFAULT '',
    batch VARCHAR(64) DEFAULT '2026',
    semester INTEGER NOT NULL DEFAULT 1,
    section VARCHAR(32) DEFAULT 'A',
    academic_year VARCHAR(32) DEFAULT '2026-2027',
    status VARCHAR(32) DEFAULT 'current', -- current, completed, transferred, withdrawn
    start_date BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT * 1000),
    end_date BIGINT,
    created_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)
);

CREATE INDEX IF NOT EXISTS idx_student_enrollments_stu ON student_enrollments(student_id);
CREATE INDEX IF NOT EXISTS idx_student_enrollments_inst ON student_enrollments(institution_id, status);

-- 3. Student Identity Verification Records
CREATE TABLE IF NOT EXISTS student_verification_records (
    id VARCHAR(64) PRIMARY KEY,
    student_id VARCHAR(64) NOT NULL REFERENCES students(id) ON DELETE CASCADE,
    verification_type VARCHAR(64) NOT NULL, -- institutional_id, document, biometrics, staff_review
    status VARCHAR(32) NOT NULL, -- VERIFIED, PENDING, REJECTED, REQUIRES_REVIEW
    verifier_id VARCHAR(64) DEFAULT '',
    notes TEXT DEFAULT '',
    verified_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)
);

CREATE INDEX IF NOT EXISTS idx_student_verif_stu ON student_verification_records(student_id);

-- 4. Student Correction Requests & Administrative Review
CREATE TABLE IF NOT EXISTS student_correction_requests (
    id VARCHAR(64) PRIMARY KEY,
    student_id VARCHAR(64) NOT NULL REFERENCES students(id) ON DELETE CASCADE,
    institution_id VARCHAR(64) NOT NULL REFERENCES tenants(id),
    field_name VARCHAR(64) NOT NULL,
    current_value TEXT DEFAULT '',
    proposed_value TEXT NOT NULL,
    reason TEXT NOT NULL,
    status VARCHAR(32) DEFAULT 'pending', -- pending, approved, rejected
    reviewed_by VARCHAR(64) DEFAULT '',
    review_notes TEXT DEFAULT '',
    created_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT * 1000),
    reviewed_at BIGINT
);

CREATE INDEX IF NOT EXISTS idx_student_corr_stu ON student_correction_requests(student_id);
CREATE INDEX IF NOT EXISTS idx_student_corr_inst ON student_correction_requests(institution_id, status);

-- 5. Bulk Student Import Jobs
CREATE TABLE IF NOT EXISTS student_import_jobs (
    id VARCHAR(64) PRIMARY KEY,
    institution_id VARCHAR(64) NOT NULL REFERENCES tenants(id),
    uploaded_by VARCHAR(64) NOT NULL,
    filename VARCHAR(256) NOT NULL,
    total_rows INTEGER DEFAULT 0,
    valid_rows INTEGER DEFAULT 0,
    invalid_rows INTEGER DEFAULT 0,
    duplicate_rows INTEGER DEFAULT 0,
    status VARCHAR(32) DEFAULT 'preview', -- preview, processing, completed, failed
    created_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT * 1000),
    completed_at BIGINT
);

CREATE INDEX IF NOT EXISTS idx_student_imports_inst ON student_import_jobs(institution_id);

-- 6. Bulk Student Import Row Results
CREATE TABLE IF NOT EXISTS student_import_row_results (
    id VARCHAR(64) PRIMARY KEY,
    job_id VARCHAR(64) NOT NULL REFERENCES student_import_jobs(id) ON DELETE CASCADE,
    row_number INTEGER NOT NULL,
    roll_no VARCHAR(64) NOT NULL,
    name VARCHAR(128) NOT NULL,
    status VARCHAR(32) NOT NULL, -- CREATED, UPDATED, SKIPPED_DUPLICATE, REJECTED
    error_reason TEXT DEFAULT '',
    created_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)
);

CREATE INDEX IF NOT EXISTS idx_student_import_rows_job ON student_import_row_results(job_id);

-- 7. Durable Student Audit Trail
CREATE TABLE IF NOT EXISTS student_audit_events (
    id VARCHAR(64) PRIMARY KEY,
    student_id VARCHAR(64) NOT NULL REFERENCES students(id) ON DELETE CASCADE,
    institution_id VARCHAR(64) NOT NULL REFERENCES tenants(id),
    actor_id VARCHAR(64) NOT NULL,
    action VARCHAR(64) NOT NULL, -- CREATED, UPDATED, VERIFIED, SUSPENDED, REACTIVATED, ARCHIVED, ENROLLED, PROGRESSED, CORRECTION_REQUESTED, CORRECTION_APPROVED
    details TEXT DEFAULT '',
    occurred_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)
);

CREATE INDEX IF NOT EXISTS idx_student_audit_stu ON student_audit_events(student_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_student_audit_inst ON student_audit_events(institution_id);

-- Grant permissions to examos_app if the role exists (e.g. self-hosted / dedicated environments)
DO $$
BEGIN
   IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'examos_app') THEN
      EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO examos_app';
   END IF;
END $$;

INSERT INTO examos_schema_migrations (component, version)
VALUES ('students', 1)
ON CONFLICT (component, version) DO NOTHING;
