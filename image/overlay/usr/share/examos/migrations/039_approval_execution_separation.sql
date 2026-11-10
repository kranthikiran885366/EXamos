BEGIN;

-- 039: approval conflict evidence, resource fingerprints, and execution separation.
--
-- The centralized approval policy engine (031) records requests, decisions and
-- append-only events.  This migration adds the durable evidence the engine needs
-- to prove that a decision and the resulting execution were independently
-- revalidated:
--   * a resource fingerprint captured at submission so later decisions and
--     executions can detect concurrent modification;
--   * structured conflict-check results for every check stage;
--   * a separate execution record so "approved" is never confused with "executed".

ALTER TABLE approval_requests
    ADD COLUMN IF NOT EXISTS resource_fingerprint TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS conflict_detail JSONB NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN IF NOT EXISTS executed_at BIGINT,
    ADD COLUMN IF NOT EXISTS executed_by VARCHAR(64),
    ADD COLUMN IF NOT EXISTS execution_reason TEXT NOT NULL DEFAULT '';

-- A policy cannot require more independent approvals than it has distinct
-- approver roles.  Independent approvers are counted by role at decision time.
ALTER TABLE approval_policies
    DROP CONSTRAINT IF EXISTS approval_policies_required_approvals_roles_check;
ALTER TABLE approval_policies
    ADD CONSTRAINT approval_policies_required_approvals_roles_check
    CHECK (required_approvals <= cardinality(approver_roles));

CREATE TABLE IF NOT EXISTS approval_conflicts (
    id VARCHAR(64) PRIMARY KEY,
    request_id VARCHAR(64) NOT NULL REFERENCES approval_requests(id),
    check_stage VARCHAR(16) NOT NULL CHECK
        (check_stage IN ('submission', 'decision', 'execution')),
    result VARCHAR(24) NOT NULL CHECK
        (result IN ('CLEAR', 'WARNING', 'BLOCKED', 'REQUIRES_REVIEW')),
    policy_version INTEGER NOT NULL,
    checked_by VARCHAR(64) NOT NULL,
    checked_by_name VARCHAR(128) NOT NULL DEFAULT '',
    checked_by_role VARCHAR(40) NOT NULL DEFAULT '',
    conflicts JSONB NOT NULL DEFAULT '[]'::jsonb,
    warnings JSONB NOT NULL DEFAULT '[]'::jsonb,
    blocking_count SMALLINT NOT NULL DEFAULT 0 CHECK (blocking_count >= 0),
    resource_fingerprint TEXT NOT NULL DEFAULT '',
    checked_at BIGINT NOT NULL DEFAULT
        (EXTRACT(EPOCH FROM clock_timestamp())::BIGINT * 1000)
);

CREATE INDEX IF NOT EXISTS idx_approval_conflicts_request
    ON approval_conflicts(request_id, checked_at DESC);
CREATE INDEX IF NOT EXISTS idx_approval_conflicts_result
    ON approval_conflicts(result, checked_at DESC);

CREATE TABLE IF NOT EXISTS approval_executions (
    id VARCHAR(64) PRIMARY KEY,
    request_id VARCHAR(64) NOT NULL REFERENCES approval_requests(id),
    actor_id VARCHAR(64) NOT NULL,
    actor_name VARCHAR(128) NOT NULL,
    actor_role VARCHAR(40) NOT NULL,
    operation VARCHAR(64) NOT NULL,
    result VARCHAR(16) NOT NULL CHECK (result IN ('completed', 'failed')),
    detail JSONB NOT NULL DEFAULT '{}'::jsonb,
    reason TEXT NOT NULL DEFAULT '',
    started_at BIGINT NOT NULL DEFAULT
        (EXTRACT(EPOCH FROM clock_timestamp())::BIGINT * 1000),
    completed_at BIGINT NOT NULL DEFAULT
        (EXTRACT(EPOCH FROM clock_timestamp())::BIGINT * 1000)
);

CREATE INDEX IF NOT EXISTS idx_approval_executions_request
    ON approval_executions(request_id, completed_at DESC);

-- Conflict checks and execution results are historical records.  They may only
-- be appended; ordinary application code cannot rewrite or delete them.
CREATE OR REPLACE FUNCTION reject_approval_conflict_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'approval conflict evidence is append-only';
END;
$$;

DROP TRIGGER IF EXISTS approval_conflicts_append_only ON approval_conflicts;
CREATE TRIGGER approval_conflicts_append_only
    BEFORE UPDATE OR DELETE ON approval_conflicts
    FOR EACH ROW EXECUTE FUNCTION reject_approval_conflict_mutation();

CREATE OR REPLACE FUNCTION reject_approval_execution_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'approval execution records are append-only';
END;
$$;

DROP TRIGGER IF EXISTS approval_executions_append_only ON approval_executions;
CREATE TRIGGER approval_executions_append_only
    BEFORE UPDATE OR DELETE ON approval_executions
    FOR EACH ROW EXECUTE FUNCTION reject_approval_execution_mutation();

INSERT INTO examos_schema_migrations(component, version)
VALUES ('approval_governance', 2)
ON CONFLICT (component, version) DO NOTHING;

COMMIT;
