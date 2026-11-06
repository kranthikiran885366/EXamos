#!/usr/bin/env bash
set -euo pipefail

if [[ "$(id -u)" -eq 0 ]]; then
    echo "Run this test as an unprivileged user; PostgreSQL refuses initdb as root." >&2
    exit 1
fi

for tool in pg_config psql createdb; do
    command -v "$tool" >/dev/null || { echo "Required tool missing: $tool" >&2; exit 1; }
done

PG_BIN="$(pg_config --bindir)"
[[ -x "$PG_BIN/initdb" && -x "$PG_BIN/pg_ctl" ]] || {
    echo "initdb and pg_ctl must be installed." >&2
    exit 1
}

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/examos-approval-test.XXXXXX")"
PORT="$((20000 + RANDOM % 20000))"

cleanup() {
    "$PG_BIN/pg_ctl" -D "$TMP_DIR/data" -m immediate stop >/dev/null 2>&1 || true
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

"$PG_BIN/initdb" -D "$TMP_DIR/data" --auth-local=trust --auth-host=trust --no-instructions >/dev/null
"$PG_BIN/pg_ctl" -D "$TMP_DIR/data" -o "-p $PORT -k $TMP_DIR" -l "$TMP_DIR/postgres.log" start >/dev/null
export PGHOST="$TMP_DIR" PGPORT="$PORT" PGUSER="$(id -un)"
createdb examos_approval_test

psql -X -v ON_ERROR_STOP=1 -d examos_approval_test <<'SQL'
CREATE TABLE examos_schema_migrations (
    component TEXT NOT NULL,
    version INTEGER NOT NULL,
    PRIMARY KEY (component, version)
);
CREATE TABLE tenants (id VARCHAR(64) PRIMARY KEY);
CREATE TABLE console_records (
    collection VARCHAR(48) NOT NULL,
    record_id VARCHAR(128) NOT NULL,
    institution_id VARCHAR(64),
    data JSONB NOT NULL,
    created_by VARCHAR(64) NOT NULL,
    updated_by VARCHAR(64) NOT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    PRIMARY KEY (collection, record_id)
);
INSERT INTO tenants VALUES ('tenant-test');
SQL

psql -X -v ON_ERROR_STOP=1 -d examos_approval_test \
    -f "$ROOT/server/migrations/031_centralized_approval_governance.sql" >/dev/null

policy_count="$(psql -X -At -v ON_ERROR_STOP=1 -d examos_approval_test \
    -c "SELECT count(*) FROM approval_policies WHERE active")"
[[ "$policy_count" == "9" ]] || {
    echo "Expected 9 active approval policies, found $policy_count." >&2
    exit 1
}

psql -X -v ON_ERROR_STOP=1 -d examos_approval_test <<'SQL'
INSERT INTO approval_requests
    (id, policy_key, policy_version, resource_type, resource_id, institution_id,
     label, reason, requester_id, requester_name, requester_role, risk_level,
     status, required_approvals)
VALUES
    ('apr_test', 'policy-publish', 1, 'policy-publish', 'pol_test', 'tenant-test',
     'Publish test', 'Migration test justification', 'requester', 'Requester',
     'INSTITUTION_ADMIN', 'critical', 'pending_review', 1);
INSERT INTO approval_decisions
    (id, request_id, actor_id, actor_name, actor_role, decision, reason, policy_version)
VALUES
    ('apd_test', 'apr_test', 'reviewer', 'Reviewer', 'SECURITY_ADMIN',
     'approved', 'Independent migration test approval', 1);
INSERT INTO approval_events
    (id, request_id, event_type, actor_id, actor_name, actor_role)
VALUES
    ('ape_test', 'apr_test', 'TEST', 'reviewer', 'Reviewer', 'SECURITY_ADMIN');
SQL

if psql -X -v ON_ERROR_STOP=1 -d examos_approval_test \
    -c "INSERT INTO approval_requests (id, policy_key, policy_version, resource_type, resource_id, institution_id, label, reason, requester_id, requester_name, requester_role, risk_level, status, required_approvals) VALUES ('apr_duplicate', 'policy-publish', 1, 'policy-publish', 'pol_test', 'tenant-test', 'Duplicate', 'Duplicate test justification', 'requester', 'Requester', 'INSTITUTION_ADMIN', 'critical', 'pending_review', 1)" >/dev/null 2>&1; then
    echo "Duplicate open request for the same resource was accepted." >&2
    exit 1
fi

if psql -X -v ON_ERROR_STOP=1 -d examos_approval_test \
    -c "UPDATE approval_decisions SET reason='tampered' WHERE id='apd_test'" >/dev/null 2>&1; then
    echo "Approval decision update was accepted." >&2
    exit 1
fi

if psql -X -v ON_ERROR_STOP=1 -d examos_approval_test \
    -c "DELETE FROM approval_events WHERE id='ape_test'" >/dev/null 2>&1; then
    echo "Approval event deletion was accepted." >&2
    exit 1
fi

echo "Approval governance migration, uniqueness, and append-only checks passed."
