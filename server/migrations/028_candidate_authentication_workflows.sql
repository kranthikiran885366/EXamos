-- Candidate authentication credentials and invigilator identity verification.
BEGIN;

CREATE TABLE IF NOT EXISTS candidate_exam_auth_tokens (
    id VARCHAR(64) PRIMARY KEY,
    examination_id VARCHAR(64) NOT NULL REFERENCES examinations(id) ON DELETE CASCADE,
    institution_id VARCHAR(64) NOT NULL,
    candidate_id VARCHAR(64) NOT NULL REFERENCES candidates(id) ON DELETE CASCADE,
    token_hash VARCHAR(64) NOT NULL UNIQUE,
    issued_by VARCHAR(64) NOT NULL,
    expires_at BIGINT NOT NULL,
    used_at BIGINT,
    revoked_at BIGINT,
    created_at BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_candidate_exam_auth_tokens_lookup
    ON candidate_exam_auth_tokens(examination_id, candidate_id, expires_at)
    WHERE used_at IS NULL AND revoked_at IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_candidate_exam_auth_tokens_active
    ON candidate_exam_auth_tokens(examination_id, candidate_id)
    WHERE used_at IS NULL AND revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS candidate_exam_checkins (
    id VARCHAR(64) PRIMARY KEY,
    examination_id VARCHAR(64) NOT NULL REFERENCES examinations(id) ON DELETE CASCADE,
    institution_id VARCHAR(64) NOT NULL,
    candidate_id VARCHAR(64) NOT NULL REFERENCES candidates(id) ON DELETE CASCADE,
    poll_token_hash VARCHAR(64) NOT NULL UNIQUE,
    status VARCHAR(16) NOT NULL CHECK (status IN ('pending', 'approved', 'rejected', 'consumed', 'expired')),
    verified_by VARCHAR(64) NOT NULL DEFAULT '',
    decision_reason TEXT NOT NULL DEFAULT '',
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    verified_at BIGINT,
    consumed_at BIGINT
);

CREATE INDEX IF NOT EXISTS idx_candidate_exam_checkins_queue
    ON candidate_exam_checkins(examination_id, status, created_at);
CREATE UNIQUE INDEX IF NOT EXISTS uq_candidate_exam_checkins_open
    ON candidate_exam_checkins(examination_id, candidate_id)
    WHERE status IN ('pending', 'approved');

INSERT INTO examos_schema_migrations(component, version)
VALUES ('candidate_authentication', 1)
ON CONFLICT (component, version) DO NOTHING;

COMMIT;
