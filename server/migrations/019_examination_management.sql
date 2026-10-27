-- ============================================================================
-- Migration 019: Examination Management (Module 9)
-- Complete exam lifecycle, multi-tenant scoping, scheduling, eligibility,
-- student assignments, ExamOS policies, approvals, audit logs, and monitoring.
-- ============================================================================

BEGIN;

-- 1. Master examinations table
CREATE TABLE IF NOT EXISTS examinations (
    id VARCHAR(64) PRIMARY KEY,
    institution_id VARCHAR(64) NOT NULL,
    code VARCHAR(32) NOT NULL,
    name VARCHAR(128) NOT NULL,
    subject VARCHAR(128) NOT NULL,
    academic_year VARCHAR(32) NOT NULL DEFAULT '',
    exam_type VARCHAR(32) NOT NULL DEFAULT 'final',
    duration_minutes INTEGER NOT NULL CHECK (duration_minutes >= 15 AND duration_minutes <= 300),
    total_marks INTEGER NOT NULL DEFAULT 100,
    passing_marks INTEGER NOT NULL DEFAULT 40,
    instructions TEXT NOT NULL DEFAULT '',
    status VARCHAR(32) NOT NULL DEFAULT 'draft' CHECK (status IN (
        'draft', 'configured', 'pending_approval', 'approved',
        'scheduled', 'ready', 'in_progress', 'closed', 'finalized', 'cancelled'
    )),
    exam_url TEXT NOT NULL DEFAULT '',
    allowed_origins TEXT NOT NULL DEFAULT '',
    policy_id VARCHAR(64),
    approved_by VARCHAR(64),
    approved_at BIGINT,
    published_at BIGINT,
    closed_at BIGINT,
    finalized_at BIGINT,
    cancelled_at BIGINT,
    cancel_reason TEXT,
    created_by VARCHAR(64) NOT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    CONSTRAINT uq_institution_exam_code UNIQUE (institution_id, code)
);

CREATE INDEX IF NOT EXISTS idx_examinations_inst ON examinations (institution_id);
CREATE INDEX IF NOT EXISTS idx_examinations_status ON examinations (status);
CREATE INDEX IF NOT EXISTS idx_examinations_created_at ON examinations (created_at DESC);

-- 2. Multi-campus & department exam schedules
CREATE TABLE IF NOT EXISTS exam_schedules (
    id VARCHAR(64) PRIMARY KEY,
    exam_id VARCHAR(64) NOT NULL REFERENCES examinations(id) ON DELETE CASCADE,
    institution_id VARCHAR(64) NOT NULL,
    campus_id VARCHAR(64),
    department_id VARCHAR(64),
    room_id VARCHAR(64),
    session_name VARCHAR(64) NOT NULL DEFAULT 'Morning Session',
    start_time BIGINT NOT NULL,
    end_time BIGINT NOT NULL,
    timezone VARCHAR(64) NOT NULL DEFAULT 'Asia/Kolkata',
    invigilator_id VARCHAR(64),
    created_at BIGINT NOT NULL,
    CHECK (end_time > start_time)
);

CREATE INDEX IF NOT EXISTS idx_exam_schedules_exam ON exam_schedules (exam_id);
CREATE INDEX IF NOT EXISTS idx_exam_schedules_inst ON exam_schedules (institution_id);

-- 3. Exam eligibility rules
CREATE TABLE IF NOT EXISTS exam_eligibility_rules (
    id VARCHAR(64) PRIMARY KEY,
    exam_id VARCHAR(64) NOT NULL REFERENCES examinations(id) ON DELETE CASCADE,
    institution_id VARCHAR(64) NOT NULL,
    course VARCHAR(128),
    department_id VARCHAR(64),
    semester INTEGER DEFAULT 1,
    minimum_attendance_pct INTEGER DEFAULT 75,
    prerequisites TEXT DEFAULT '',
    created_at BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_exam_eligibility_exam ON exam_eligibility_rules (exam_id);

-- 4. Candidate / Student assignments
CREATE TABLE IF NOT EXISTS exam_student_assignments (
    id VARCHAR(64) PRIMARY KEY,
    exam_id VARCHAR(64) NOT NULL REFERENCES examinations(id) ON DELETE CASCADE,
    institution_id VARCHAR(64) NOT NULL,
    student_id VARCHAR(64) NOT NULL,
    roll_no VARCHAR(64) NOT NULL,
    name VARCHAR(128) NOT NULL,
    campus_id VARCHAR(64),
    department_id VARCHAR(64),
    room_id VARCHAR(64),
    seat_no VARCHAR(32) DEFAULT '',
    assigned_device_id VARCHAR(64) DEFAULT '',
    eligibility_status VARCHAR(32) NOT NULL DEFAULT 'eligible' CHECK (eligibility_status IN ('eligible', 'ineligible', 'exempted')),
    pin_hash VARCHAR(128) DEFAULT '',
    created_at BIGINT NOT NULL,
    CONSTRAINT uq_exam_student UNIQUE (exam_id, student_id)
);

CREATE INDEX IF NOT EXISTS idx_exam_student_assign_exam ON exam_student_assignments (exam_id);

-- 5. ExamOS appliance environment policies
CREATE TABLE IF NOT EXISTS exam_os_policies (
    id VARCHAR(64) PRIMARY KEY,
    exam_id VARCHAR(64) NOT NULL REFERENCES examinations(id) ON DELETE CASCADE,
    institution_id VARCHAR(64) NOT NULL,
    required_os_release VARCHAR(64) NOT NULL DEFAULT 'ExamOS-2026.1',
    permitted_application VARCHAR(128) NOT NULL DEFAULT 'examos-kiosk-browser',
    url_policy TEXT NOT NULL DEFAULT '',
    network_rules_json TEXT NOT NULL DEFAULT '{"default":"drop","allow":[]}',
    require_tpm BOOLEAN NOT NULL DEFAULT true,
    require_secure_boot BOOLEAN NOT NULL DEFAULT true,
    kiosk_lockdown BOOLEAN NOT NULL DEFAULT true,
    block_usb BOOLEAN NOT NULL DEFAULT true,
    block_clipboard BOOLEAN NOT NULL DEFAULT true,
    block_screen_capture BOOLEAN NOT NULL DEFAULT true,
    policy_signature VARCHAR(64) DEFAULT '',
    created_at BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_exam_os_policies_exam ON exam_os_policies (exam_id);

-- 6. Exam review and approval audit records (Separation of duties)
CREATE TABLE IF NOT EXISTS exam_approvals (
    id VARCHAR(64) PRIMARY KEY,
    exam_id VARCHAR(64) NOT NULL REFERENCES examinations(id) ON DELETE CASCADE,
    institution_id VARCHAR(64) NOT NULL,
    decision VARCHAR(32) NOT NULL CHECK (decision IN ('approved', 'rejected')),
    approver_user_id VARCHAR(64) NOT NULL,
    notes TEXT DEFAULT '',
    checklist_json TEXT DEFAULT '{}',
    created_at BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_exam_approvals_exam ON exam_approvals (exam_id);

-- 7. Exam lifecycle state transition history
CREATE TABLE IF NOT EXISTS exam_status_history (
    id VARCHAR(64) PRIMARY KEY,
    exam_id VARCHAR(64) NOT NULL REFERENCES examinations(id) ON DELETE CASCADE,
    from_status VARCHAR(32) NOT NULL,
    to_status VARCHAR(32) NOT NULL,
    actor_id VARCHAR(64) NOT NULL,
    reason TEXT DEFAULT '',
    created_at BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_exam_status_history_exam ON exam_status_history (exam_id);

-- 8. Student exam attempts for real-time monitoring
CREATE TABLE IF NOT EXISTS exam_attempts (
    id VARCHAR(64) PRIMARY KEY,
    exam_id VARCHAR(64) NOT NULL REFERENCES examinations(id) ON DELETE CASCADE,
    student_id VARCHAR(64) NOT NULL,
    device_id VARCHAR(64) DEFAULT '',
    status VARCHAR(32) NOT NULL DEFAULT 'ready' CHECK (status IN (
        'scheduled', 'ready', 'in_progress', 'submitted', 'interrupted', 'completed'
    )),
    start_time BIGINT DEFAULT 0,
    submit_time BIGINT DEFAULT 0,
    score DOUBLE PRECISION DEFAULT 0.0,
    created_at BIGINT NOT NULL,
    CONSTRAINT uq_exam_student_attempt UNIQUE (exam_id, student_id)
);

CREATE INDEX IF NOT EXISTS idx_exam_attempts_exam_status ON exam_attempts (exam_id, status);

-- 9. Real-time invigilation & security events
CREATE TABLE IF NOT EXISTS exam_events (
    id VARCHAR(64) PRIMARY KEY,
    exam_id VARCHAR(64) NOT NULL REFERENCES examinations(id) ON DELETE CASCADE,
    attempt_id VARCHAR(64),
    device_id VARCHAR(64) DEFAULT '',
    student_id VARCHAR(64) DEFAULT '',
    event_type VARCHAR(64) NOT NULL,
    details TEXT DEFAULT '',
    severity VARCHAR(32) NOT NULL DEFAULT 'info',
    created_at BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_exam_events_exam ON exam_events (exam_id);

-- 10. Immutable audit logs for exam operations
CREATE TABLE IF NOT EXISTS exam_audit_logs (
    id VARCHAR(64) PRIMARY KEY,
    exam_id VARCHAR(64) NOT NULL REFERENCES examinations(id) ON DELETE CASCADE,
    institution_id VARCHAR(64) NOT NULL,
    actor_id VARCHAR(64) NOT NULL,
    action VARCHAR(64) NOT NULL,
    change_summary TEXT DEFAULT '',
    created_at BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_exam_audit_logs_exam ON exam_audit_logs (exam_id);

-- Seed backwards-compatibility trigger or copy if exams table exists
INSERT INTO examinations (
    id, institution_id, code, name, subject, academic_year, exam_type,
    duration_minutes, total_marks, passing_marks, instructions, status,
    exam_url, allowed_origins, policy_id, created_by, created_at, updated_at
)
SELECT
    id,
    COALESCE(tenant_id, 'inst_demo'),
    COALESCE(code, SUBSTRING(id FROM 5 FOR 8)),
    COALESCE(title, 'Untitled Exam'),
    COALESCE(course, 'General'),
    COALESCE(academic_year, '2026-2027'),
    COALESCE(type, 'final'),
    COALESCE(duration_min, 60),
    100,
    40,
    COALESCE(instructions, ''),
    CASE 
        WHEN status = 'DRAFT' OR status = 'draft' THEN 'draft'
        WHEN status = 'VALIDATED' OR status = 'review' THEN 'configured'
        WHEN status = 'APPROVED' OR status = 'approved' THEN 'approved'
        WHEN status = 'SCHEDULED' OR status = 'published' THEN 'scheduled'
        WHEN status = 'OPEN' OR status = 'ready' THEN 'ready'
        WHEN status = 'ACTIVE' OR status = 'live' THEN 'in_progress'
        WHEN status = 'SUBMISSION' OR status = 'closed' THEN 'closed'
        WHEN status = 'RECONCILED' OR status = 'finalized' THEN 'finalized'
        WHEN status = 'cancelled' THEN 'cancelled'
        ELSE 'draft'
    END,
    COALESCE(allowed_destinations->>0, 'https://exam.university.edu'),
    COALESCE(origins->>0, ''),
    policy_id,
    COALESCE(created_by, 'root'),
    COALESCE(created_at, EXTRACT(EPOCH FROM NOW())::BIGINT * 1000),
    COALESCE(updated_at, EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)
FROM exams
ON CONFLICT (id) DO NOTHING;

INSERT INTO examos_schema_migrations (component, version, notes)
VALUES ('examination_management', 19, 'Module 9 Examination Management');

COMMIT;
