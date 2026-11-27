-- Migration 053: Architecture Briefing Lead Capture
-- Persists public architecture briefing requests submitted from the SPPIO landing page
-- so leads are stored durably in PostgreSQL instead of relying on mailto: drafts.

CREATE TABLE IF NOT EXISTS briefing_requests (
    id              VARCHAR(64) PRIMARY KEY,
    full_name       VARCHAR(160) NOT NULL,
    email           VARCHAR(160) NOT NULL,
    organization    VARCHAR(200) NOT NULL,
    fleet_size      VARCHAR(64)  NOT NULL DEFAULT '50-500',
    message         TEXT         NOT NULL DEFAULT '',
    status          VARCHAR(32)  NOT NULL DEFAULT 'NEW',
    created_at      BIGINT       NOT NULL DEFAULT (EXTRACT(EPOCH FROM NOW())::BIGINT * 1000)
);

CREATE INDEX IF NOT EXISTS idx_briefing_requests_created_at
    ON briefing_requests (created_at DESC);
