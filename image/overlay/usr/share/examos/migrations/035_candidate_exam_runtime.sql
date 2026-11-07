BEGIN;

ALTER TABLE candidate_exam_checkins
    ADD COLUMN IF NOT EXISTS exam_session_id VARCHAR(64)
        REFERENCES exam_sessions(id);

ALTER TABLE candidate_exam_checkins
    DROP CONSTRAINT IF EXISTS candidate_exam_checkins_status_check;
ALTER TABLE candidate_exam_checkins
    ADD CONSTRAINT candidate_exam_checkins_status_check
        CHECK (status IN ('pending', 'approved', 'attesting', 'rejected', 'consumed', 'expired'));

DROP INDEX IF EXISTS uq_candidate_exam_checkins_open;
CREATE UNIQUE INDEX uq_candidate_exam_checkins_open
    ON candidate_exam_checkins(examination_id, candidate_id)
    WHERE status IN ('pending', 'approved', 'attesting');

ALTER TABLE auth_sessions
    ADD COLUMN IF NOT EXISTS exam_session_id VARCHAR(64)
        REFERENCES exam_sessions(id);

CREATE UNIQUE INDEX IF NOT EXISTS uq_candidate_checkin_exam_session
    ON candidate_exam_checkins(exam_session_id)
    WHERE exam_session_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_exam_sessions_attestation_queue
    ON exam_sessions(device_id, created_at)
    WHERE status = 'pending' AND device_id <> '';
CREATE INDEX IF NOT EXISTS idx_auth_sessions_exam_session
    ON auth_sessions(exam_session_id)
    WHERE exam_session_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS candidate_exam_consents (
    exam_session_id VARCHAR(64) PRIMARY KEY REFERENCES exam_sessions(id),
    candidate_id VARCHAR(64) NOT NULL REFERENCES candidates(id),
    consent_version VARCHAR(32) NOT NULL,
    consented_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS candidate_exam_answers (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    exam_session_id VARCHAR(64) NOT NULL REFERENCES exam_sessions(id),
    question_id BIGINT NOT NULL REFERENCES examos_exam_questions(question_id),
    answer_text TEXT NOT NULL,
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision > 0),
    saved_at BIGINT NOT NULL,
    UNIQUE (exam_session_id, question_id)
);

CREATE INDEX IF NOT EXISTS idx_candidate_exam_answers_session
    ON candidate_exam_answers(exam_session_id, question_id);

CREATE TABLE IF NOT EXISTS candidate_exam_submissions (
    exam_session_id VARCHAR(64) PRIMARY KEY REFERENCES exam_sessions(id),
    receipt_id VARCHAR(64) NOT NULL UNIQUE,
    candidate_id VARCHAR(64) NOT NULL,
    examination_id VARCHAR(64) NOT NULL,
    answer_count INTEGER NOT NULL CHECK (answer_count >= 0),
    answers_sha256 CHAR(64) NOT NULL CHECK (answers_sha256 ~ '^[0-9a-f]{64}$'),
    submitted_at BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_candidate_exam_submissions_exam
    ON candidate_exam_submissions(examination_id, submitted_at DESC);

INSERT INTO examos_schema_migrations(component, version)
VALUES ('candidate_exam_runtime', 1)
ON CONFLICT (component, version) DO NOTHING;

COMMIT;
