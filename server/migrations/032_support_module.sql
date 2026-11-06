-- 032_support_module.sql — SPPIO / ExamOS Support module
-- Dedicated, normalized PostgreSQL tables for the Support platform:
-- support requests, comments, append-only events, and recovery cases.
-- Reuses examos_institutions / examos_admin_users and the centralized
-- approval governance (approval_policies / approval_requests) for recovery.
--
-- This replaces the opaque console_records JSON-blob store for the support
-- collection with first-class, constraint-backed records so that validation,
-- status transitions, SLA, tenant isolation and audit are enforceable in the
-- database and the C backend rather than only in the browser.

BEGIN;

-- Monotonic, race-safe ticket numbering (SUP-3001, SUP-3002, ...).
CREATE SEQUENCE IF NOT EXISTS support_ticket_seq START WITH 3001;

CREATE TABLE IF NOT EXISTS support_requests (
    id                VARCHAR(64) PRIMARY KEY,
    ticket_no         VARCHAR(32) NOT NULL UNIQUE,
    institution_id    VARCHAR(63) NOT NULL
                        REFERENCES examos_institutions(institution_id) ON DELETE CASCADE,
    subject           VARCHAR(140) NOT NULL CHECK (length(subject) >= 5),
    description       TEXT NOT NULL CHECK (length(description) >= 10),
    category          VARCHAR(24) NOT NULL CHECK (category IN
                        ('device','exam','access','policy','billing','data','other')),
    priority          VARCHAR(12) NOT NULL CHECK (priority IN
                        ('critical','high','normal','low')),
    status            VARCHAR(16) NOT NULL DEFAULT 'new' CHECK (status IN
                        ('new','assigned','waiting','in-progress','resolved',
                         'closed','reopened','cancelled')),
    requester_id      VARCHAR(63) NOT NULL,
    requester_name    VARCHAR(127) NOT NULL DEFAULT '',
    assignee_id       VARCHAR(63)
                        REFERENCES examos_admin_users(user_id) ON DELETE SET NULL,
    incident_id       VARCHAR(63),
    linked_device_id  VARCHAR(63),
    linked_exam_id    VARCHAR(63),
    -- SLA deadline in epoch milliseconds (server-computed from priority).
    sla_due_at        BIGINT NOT NULL,
    first_response_at BIGINT,
    resolved_at       BIGINT,
    closed_at         BIGINT,
    resolution        TEXT NOT NULL DEFAULT '',
    escalation_reason TEXT NOT NULL DEFAULT '',
    satisfaction_score SMALLINT CHECK (satisfaction_score IS NULL
                        OR satisfaction_score BETWEEN 1 AND 5),
    created_at        BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM clock_timestamp())::BIGINT * 1000),
    updated_at        BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM clock_timestamp())::BIGINT * 1000),
    CHECK (sla_due_at > created_at)
);

CREATE INDEX IF NOT EXISTS idx_support_requests_institution_status
    ON support_requests (institution_id, status);
CREATE INDEX IF NOT EXISTS idx_support_requests_institution_created
    ON support_requests (institution_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_support_requests_assignee
    ON support_requests (assignee_id) WHERE assignee_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_support_requests_sla
    ON support_requests (status, sla_due_at) WHERE status IN ('new','assigned','waiting','in-progress','reopened');

CREATE TABLE IF NOT EXISTS support_comments (
    id          VARCHAR(64) PRIMARY KEY,
    request_id  VARCHAR(64) NOT NULL
                  REFERENCES support_requests(id) ON DELETE CASCADE,
    author_id   VARCHAR(63) NOT NULL,
    author_name VARCHAR(127) NOT NULL DEFAULT '',
    body        TEXT NOT NULL CHECK (length(body) >= 2),
    internal    BOOLEAN NOT NULL DEFAULT FALSE,
    created_at  BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM clock_timestamp())::BIGINT * 1000)
);
CREATE INDEX IF NOT EXISTS idx_support_comments_request
    ON support_comments (request_id, created_at);

-- Append-only lifecycle audit per request.
CREATE TABLE IF NOT EXISTS support_events (
    id          VARCHAR(64) PRIMARY KEY,
    request_id  VARCHAR(64) NOT NULL
                  REFERENCES support_requests(id) ON DELETE CASCADE,
    actor_id    VARCHAR(63) NOT NULL,
    event_type  VARCHAR(48) NOT NULL,
    detail      TEXT NOT NULL DEFAULT '',
    created_at  BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM clock_timestamp())::BIGINT * 1000)
);
CREATE INDEX IF NOT EXISTS idx_support_events_request
    ON support_events (request_id, created_at);

CREATE OR REPLACE FUNCTION reject_support_event_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'support event history is append-only';
END;
$$;
DROP TRIGGER IF EXISTS support_events_append_only ON support_events;
CREATE TRIGGER support_events_append_only
    BEFORE UPDATE OR DELETE ON support_events
    FOR EACH ROW EXECUTE FUNCTION reject_support_event_mutation();

CREATE TABLE IF NOT EXISTS support_recoveries (
    id                  VARCHAR(64) PRIMARY KEY,
    request_id          VARCHAR(64) NOT NULL
                          REFERENCES support_requests(id) ON DELETE CASCADE,
    institution_id      VARCHAR(63) NOT NULL,
    kind                VARCHAR(24) NOT NULL CHECK (kind IN
                          ('account-access','device-trust','usb-custody',
                           'exam-session','data-restore')),
    target              VARCHAR(80) NOT NULL CHECK (length(target) >= 1),
    -- Derived live from the linked approval_request; persisted for history.
    state               VARCHAR(24) NOT NULL DEFAULT 'pending-approval' CHECK (state IN
                          ('pending-approval','approved','rejected','executing',
                           'completed','failed','withdrawn')),
    approval_request_id VARCHAR(64)
                          REFERENCES approval_requests(id) ON DELETE SET NULL,
    requested_by        VARCHAR(63) NOT NULL,
    reason              TEXT NOT NULL CHECK (length(reason) >= 10),
    created_at          BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM clock_timestamp())::BIGINT * 1000),
    updated_at          BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM clock_timestamp())::BIGINT * 1000)
);
CREATE INDEX IF NOT EXISTS idx_support_recoveries_institution
    ON support_recoveries (institution_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_support_recoveries_request
    ON support_recoveries (request_id);

-- Centralized approval policy for high-risk recovery operations.
-- requester_permission = AUTH_PERM_INSTITUTION_ADMIN (1<<5 = 32): only
-- institution admins / platform owners may request recovery. Approver roles
-- are platform owner (1) and institution admin (2). Required approvals = 1.
INSERT INTO approval_policies
    (policy_key, version, requester_permission, approver_roles, required_approvals,
     risk_level, minimum_reason_length)
VALUES
    ('support-recovery', 1, 32, ARRAY[1,2]::smallint[], 1, 'high', 10)
ON CONFLICT (policy_key, version) DO NOTHING;

INSERT INTO examos_schema_migrations (component, version)
VALUES ('support_module', 1)
ON CONFLICT (component, version) DO NOTHING;

COMMIT;
