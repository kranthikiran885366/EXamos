-- Migration 017: Session Risk Telemetry Table
-- Purpose: Persist in-memory g_risk_states to PostgreSQL for restart-safe
--          proctoring state persistence (ISS-03 resolution).
--
-- Supersedes: volatile static session_risk_state_t g_risk_states[512] in server/main.c

BEGIN;

CREATE TABLE IF NOT EXISTS examos_session_risk (
    session_id          VARCHAR(64)     NOT NULL,
    candidate_id        VARCHAR(64)     NOT NULL DEFAULT 'UNKNOWN',
    exam_id             VARCHAR(128)    NOT NULL DEFAULT 'UNKNOWN',
    score               NUMERIC(5,2)    NOT NULL DEFAULT 0.00,
    risk_level          VARCHAR(16)     NOT NULL DEFAULT 'NORMAL',
    should_terminate    BOOLEAN         NOT NULL DEFAULT FALSE,
    face_absent_count   INTEGER         NOT NULL DEFAULT 0,
    multiple_faces_count INTEGER        NOT NULL DEFAULT 0,
    blur_count          INTEGER         NOT NULL DEFAULT 0,
    window_blur_count   INTEGER         NOT NULL DEFAULT 0,
    anomaly_count       INTEGER         NOT NULL DEFAULT 0,
    last_event_type     VARCHAR(64),
    created_at          TIMESTAMPTZ     NOT NULL DEFAULT clock_timestamp(),
    updated_at          TIMESTAMPTZ     NOT NULL DEFAULT clock_timestamp(),

    CONSTRAINT examos_session_risk_pkey PRIMARY KEY (session_id),
    CONSTRAINT examos_session_risk_score_range CHECK (score >= 0.00 AND score <= 100.00)
);

-- Index: look up by candidate for exam review dashboards
CREATE INDEX IF NOT EXISTS idx_session_risk_candidate_updated
    ON examos_session_risk (candidate_id, updated_at DESC);

-- Index: quickly find sessions that should be terminated (invigilator alert polling)
CREATE INDEX IF NOT EXISTS idx_session_risk_terminate
    ON examos_session_risk (exam_id, should_terminate)
    WHERE should_terminate = TRUE;

-- Index: high-risk sessions for analytics
CREATE INDEX IF NOT EXISTS idx_session_risk_score
    ON examos_session_risk (score DESC)
    WHERE score > 50.00;

COMMENT ON TABLE examos_session_risk IS
    'Persistent mirror of the in-memory session risk engine state. '
    'Updated via UPSERT on every proctoring event. Survives server restart.';

COMMENT ON COLUMN examos_session_risk.session_id IS
    'Candidate session token (same as examos_candidate_sessions.token). '
    'Used as the primary correlation key.';

COMMENT ON COLUMN examos_session_risk.score IS
    'Composite risk score 0.00-100.00 from risk_engine_evaluate(). '
    'Thresholds: NORMAL < 25, ELEVATED 25-49, HIGH 50-74, CRITICAL >= 75.';

COMMENT ON COLUMN examos_session_risk.should_terminate IS
    'TRUE when the risk engine recommends session termination. '
    'Invigilator must confirm before the server invalidates the session.';

-- Add notes column to the migration registry if not already present.
-- This column was referenced in this migration but never added to the schema
-- created in migration 001.  ALTER TABLE ... ADD COLUMN IF NOT EXISTS is
-- idempotent so it is safe to run on a cluster where the column was added
-- by another route.
ALTER TABLE examos_schema_migrations
    ADD COLUMN IF NOT EXISTS notes text;

-- Record migration
INSERT INTO examos_schema_migrations (component, version, applied_at, notes)
VALUES (
    'operations',
    2,
    clock_timestamp(),
    'Initial session risk persistence table (ISS-03 resolution). '
    'Enables restart-safe proctoring anomaly tracking and invigilator alert polling.'
)
ON CONFLICT (component, version) DO NOTHING;

COMMIT;
