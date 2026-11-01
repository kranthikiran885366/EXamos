-- 021_exam_session_management.sql
-- Module 11: Exam Session Management
-- Session lifecycle, launch authorization tokens, session policies, device bindings, and audit trail

-- 1. Main session record and lifecycle state
CREATE TABLE IF NOT EXISTS exam_sessions (
    id VARCHAR(64) PRIMARY KEY,
    institution_id VARCHAR(64) NOT NULL,
    examination_id VARCHAR(64) NOT NULL,
    student_id VARCHAR(64) NOT NULL,
    device_id VARCHAR(64) NOT NULL DEFAULT '',
    status VARCHAR(32) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'authorized', 'launching', 'active', 'interrupted', 'resuming', 'closed')),
    authorized_at BIGINT,
    launched_at BIGINT,
    last_heartbeat_at BIGINT,
    interrupted_at BIGINT,
    closed_at BIGINT,
    closure_reason VARCHAR(128) NOT NULL DEFAULT '',
    interruption_count INT NOT NULL DEFAULT 0,
    policy_version INT NOT NULL DEFAULT 1,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_exam_sessions_inst_exam ON exam_sessions(institution_id, examination_id);
CREATE INDEX IF NOT EXISTS idx_exam_sessions_stu_exam ON exam_sessions(student_id, examination_id);
CREATE INDEX IF NOT EXISTS idx_exam_sessions_status ON exam_sessions(status);

-- 2. Lifecycle event logs
CREATE TABLE IF NOT EXISTS exam_session_events (
    id VARCHAR(64) PRIMARY KEY,
    session_id VARCHAR(64) NOT NULL REFERENCES exam_sessions(id) ON DELETE CASCADE,
    examination_id VARCHAR(64) NOT NULL,
    institution_id VARCHAR(64) NOT NULL,
    event_type VARCHAR(64) NOT NULL CHECK (event_type IN ('authorized', 'launch_requested', 'launched', 'heartbeat', 'interruption_detected', 'resume_requested', 'resumed', 'closed', 'expired')),
    payload_json TEXT NOT NULL DEFAULT '{}',
    created_at BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_exam_session_events_session ON exam_session_events(session_id);
CREATE INDEX IF NOT EXISTS idx_exam_session_events_created ON exam_session_events(created_at);

-- 3. Short-lived launch authorization tokens
CREATE TABLE IF NOT EXISTS exam_launch_authorizations (
    id VARCHAR(64) PRIMARY KEY,
    session_id VARCHAR(64) NOT NULL REFERENCES exam_sessions(id) ON DELETE CASCADE,
    token_hash VARCHAR(128) NOT NULL,
    exam_url TEXT NOT NULL,
    allowed_origins TEXT NOT NULL DEFAULT '*',
    expires_at BIGINT NOT NULL,
    used_at BIGINT,
    created_at BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_exam_launch_auth_token ON exam_launch_authorizations(token_hash);
CREATE INDEX IF NOT EXISTS idx_exam_launch_auth_session ON exam_launch_authorizations(session_id);

-- 4. Session policies (re-entry, timeout, interruption thresholds)
CREATE TABLE IF NOT EXISTS exam_session_policies (
    id VARCHAR(64) PRIMARY KEY,
    institution_id VARCHAR(64) NOT NULL,
    examination_id VARCHAR(64) NOT NULL UNIQUE,
    max_interruptions INT NOT NULL DEFAULT 3,
    heartbeat_interval_sec INT NOT NULL DEFAULT 15,
    heartbeat_timeout_sec INT NOT NULL DEFAULT 60,
    reconnect_window_sec INT NOT NULL DEFAULT 600,
    allow_reentry BOOLEAN NOT NULL DEFAULT TRUE,
    allow_concurrent_sessions BOOLEAN NOT NULL DEFAULT FALSE,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);

-- 5. Links sessions to registered device identities
CREATE TABLE IF NOT EXISTS exam_session_devices (
    id VARCHAR(64) PRIMARY KEY,
    session_id VARCHAR(64) NOT NULL REFERENCES exam_sessions(id) ON DELETE CASCADE,
    device_id VARCHAR(64) NOT NULL,
    tpm_enrolled BOOLEAN NOT NULL DEFAULT FALSE,
    os_release VARCHAR(64) NOT NULL DEFAULT 'ExamOS 2.0',
    mac_address VARCHAR(32) NOT NULL DEFAULT '',
    ip_address VARCHAR(45) NOT NULL DEFAULT '',
    bound_at BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_exam_session_devices_session ON exam_session_devices(session_id);
CREATE INDEX IF NOT EXISTS idx_exam_session_devices_device ON exam_session_devices(device_id);

-- 6. Administrative actions and security-relevant decisions
CREATE TABLE IF NOT EXISTS exam_session_audit_logs (
    id VARCHAR(64) PRIMARY KEY,
    session_id VARCHAR(64) NOT NULL,
    examination_id VARCHAR(64) NOT NULL,
    institution_id VARCHAR(64) NOT NULL,
    actor_id VARCHAR(64) NOT NULL,
    action VARCHAR(64) NOT NULL,
    details TEXT NOT NULL DEFAULT '',
    created_at BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_exam_session_audit_session ON exam_session_audit_logs(session_id);
CREATE INDEX IF NOT EXISTS idx_exam_session_audit_exam ON exam_session_audit_logs(examination_id);

INSERT INTO examos_schema_migrations (component, version)
VALUES ('exam_lifecycle', 6)
ON CONFLICT (component, version) DO NOTHING;
