BEGIN;

CREATE TABLE IF NOT EXISTS approval_policies (
    policy_key VARCHAR(64) NOT NULL,
    version INTEGER NOT NULL CHECK (version > 0),
    requester_permission INTEGER NOT NULL,
    approver_roles SMALLINT[] NOT NULL CHECK (cardinality(approver_roles) > 0),
    required_approvals SMALLINT NOT NULL DEFAULT 1 CHECK (required_approvals > 0),
    risk_level VARCHAR(16) NOT NULL CHECK (risk_level IN ('low', 'medium', 'high', 'critical')),
    minimum_reason_length SMALLINT NOT NULL DEFAULT 8 CHECK (minimum_reason_length BETWEEN 5 AND 300),
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM clock_timestamp())::BIGINT * 1000),
    PRIMARY KEY (policy_key, version)
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_approval_policies_active
    ON approval_policies(policy_key) WHERE active = TRUE;

INSERT INTO approval_policies
    (policy_key, version, requester_permission, approver_roles, required_approvals, risk_level, minimum_reason_length)
VALUES
    ('role-change', 1, 16, ARRAY[1]::smallint[], 1, 'critical', 8),
    ('release-approve', 1, 4, ARRAY[1, 4]::smallint[], 1, 'critical', 8),
    ('policy-publish', 1, 2, ARRAY[1, 4]::smallint[], 1, 'critical', 8),
    ('policy-rollback', 1, 8, ARRAY[1, 4]::smallint[], 1, 'high', 8),
    ('config-change', 1, 32, ARRAY[1]::smallint[], 1, 'critical', 8),
    ('device-reauth', 1, 4, ARRAY[1, 4, 2]::smallint[], 1, 'high', 8),
    ('exam-approve', 1, 2, ARRAY[1, 2, 3]::smallint[], 1, 'high', 8),
    ('billing-change', 1, 32, ARRAY[1, 2]::smallint[], 1, 'medium', 8),
    ('privacy-deletion', 1, 32, ARRAY[1, 2]::smallint[], 1, 'high', 8)
ON CONFLICT (policy_key, version) DO NOTHING;

CREATE TABLE IF NOT EXISTS approval_requests (
    id VARCHAR(64) PRIMARY KEY,
    policy_key VARCHAR(64) NOT NULL,
    policy_version INTEGER NOT NULL,
    resource_type VARCHAR(64) NOT NULL,
    resource_id VARCHAR(128) NOT NULL,
    institution_id VARCHAR(64),
    label VARCHAR(140) NOT NULL,
    reason TEXT NOT NULL,
    proposed_data JSONB NOT NULL DEFAULT '{}'::jsonb,
    requester_id VARCHAR(64) NOT NULL,
    requester_name VARCHAR(128) NOT NULL,
    requester_role VARCHAR(40) NOT NULL,
    risk_level VARCHAR(16) NOT NULL,
    status VARCHAR(32) NOT NULL CHECK (status IN
        ('pending_review', 'approved', 'execution_pending', 'executing', 'completed',
         'rejected', 'changes_requested', 'withdrawn', 'blocked', 'expired', 'failed')),
    conflict_status VARCHAR(24) NOT NULL DEFAULT 'WARNING' CHECK
        (conflict_status IN ('CLEAR', 'WARNING', 'BLOCKED', 'REQUIRES_REVIEW')),
    required_approvals SMALLINT NOT NULL CHECK (required_approvals > 0),
    execution_status VARCHAR(32) NOT NULL DEFAULT 'not_started' CHECK
        (execution_status IN ('not_started', 'pending_integration', 'executing', 'completed', 'failed')),
    created_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM clock_timestamp())::BIGINT * 1000),
    updated_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM clock_timestamp())::BIGINT * 1000),
    expires_at BIGINT NOT NULL DEFAULT
        ((EXTRACT(EPOCH FROM clock_timestamp())::BIGINT + 2592000) * 1000),
    FOREIGN KEY (policy_key, policy_version)
        REFERENCES approval_policies(policy_key, version)
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_approval_requests_open_resource
    ON approval_requests(policy_key, resource_type, resource_id, COALESCE(institution_id, ''))
    WHERE status IN ('pending_review', 'approved', 'execution_pending', 'executing');
CREATE INDEX IF NOT EXISTS idx_approval_requests_requester
    ON approval_requests(requester_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_approval_requests_institution
    ON approval_requests(institution_id, status, created_at DESC);

CREATE TABLE IF NOT EXISTS approval_decisions (
    id VARCHAR(64) PRIMARY KEY,
    request_id VARCHAR(64) NOT NULL REFERENCES approval_requests(id),
    actor_id VARCHAR(64) NOT NULL,
    actor_name VARCHAR(128) NOT NULL,
    actor_role VARCHAR(40) NOT NULL,
    decision VARCHAR(24) NOT NULL CHECK
        (decision IN ('approved', 'rejected', 'changes_requested')),
    reason TEXT NOT NULL,
    policy_version INTEGER NOT NULL,
    occurred_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM clock_timestamp())::BIGINT * 1000),
    UNIQUE (request_id, actor_id)
);
CREATE INDEX IF NOT EXISTS idx_approval_decisions_request
    ON approval_decisions(request_id, occurred_at);

CREATE TABLE IF NOT EXISTS approval_events (
    id VARCHAR(64) PRIMARY KEY,
    request_id VARCHAR(64) NOT NULL REFERENCES approval_requests(id),
    event_type VARCHAR(40) NOT NULL,
    actor_id VARCHAR(64) NOT NULL,
    actor_name VARCHAR(128) NOT NULL,
    actor_role VARCHAR(40) NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    occurred_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM clock_timestamp())::BIGINT * 1000)
);
CREATE INDEX IF NOT EXISTS idx_approval_events_request
    ON approval_events(request_id, occurred_at);

CREATE OR REPLACE FUNCTION reject_approval_event_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'approval event history is append-only';
END;
$$;

DROP TRIGGER IF EXISTS approval_events_append_only ON approval_events;
CREATE TRIGGER approval_events_append_only
    BEFORE UPDATE OR DELETE ON approval_events
    FOR EACH ROW EXECUTE FUNCTION reject_approval_event_mutation();

CREATE OR REPLACE FUNCTION reject_approval_decision_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'approval decisions are append-only';
END;
$$;

DROP TRIGGER IF EXISTS approval_decisions_append_only ON approval_decisions;
CREATE TRIGGER approval_decisions_append_only
    BEFORE UPDATE OR DELETE ON approval_decisions
    FOR EACH ROW EXECUTE FUNCTION reject_approval_decision_mutation();

INSERT INTO examos_schema_migrations(component, version)
VALUES ('approval_governance', 1)
ON CONFLICT (component, version) DO NOTHING;

COMMIT;
