#!/usr/bin/env bash
set -euo pipefail

if [[ "$(id -u)" -eq 0 ]]; then
    echo "Run this test as an unprivileged user; PostgreSQL refuses initdb as root." >&2
    exit 1
fi

for tool in pg_config psql createdb; do
    command -v "$tool" >/dev/null || {
        echo "Required tool missing: $tool" >&2
        exit 1
    }
done

PG_BIN="$(pg_config --bindir)"
[[ -x "$PG_BIN/initdb" && -x "$PG_BIN/pg_ctl" ]] || {
    echo "initdb and pg_ctl must be installed." >&2
    exit 1
}

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/examos-policy-activation-test.XXXXXX")"
PORT="$((20000 + RANDOM % 20000))"

cleanup() {
    "$PG_BIN/pg_ctl" -D "$TMP_DIR/data" -m immediate stop >/dev/null 2>&1 || true
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

"$PG_BIN/initdb" -D "$TMP_DIR/data" --auth-local=trust --auth-host=trust --no-instructions >/dev/null
"$PG_BIN/pg_ctl" -D "$TMP_DIR/data" -o "-p $PORT -k $TMP_DIR" -l "$TMP_DIR/postgres.log" start >/dev/null
export PGHOST="$TMP_DIR" PGPORT="$PORT" PGUSER="$(id -un)"
createdb examos_policy_activation_test

psql -X -v ON_ERROR_STOP=1 -d examos_policy_activation_test <<'SQL'
CREATE TABLE examos_schema_migrations (
    component TEXT NOT NULL,
    version INTEGER NOT NULL,
    PRIMARY KEY (component, version)
);
CREATE TABLE examos_exam_policies (
    policy_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    exam_id VARCHAR(63) NOT NULL,
    policy_version INTEGER NOT NULL,
    exam_url TEXT NOT NULL,
    allowed_origins TEXT NOT NULL DEFAULT '',
    permitted_apps TEXT NOT NULL DEFAULT '',
    signature VARCHAR(64) NOT NULL,
    approved_by VARCHAR(63),
    status VARCHAR(31) NOT NULL CHECK (status IN ('ACTIVE','SUPERSEDED','ROLLBACK')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
INSERT INTO examos_exam_policies
    (exam_id,policy_version,exam_url,signature,status)
VALUES
    ('exam-history',1,'https://exam.example.test','legacy-hmac','ACTIVE'),
    ('exam-history',2,'https://exam.example.test','legacy-hmac','SUPERSEDED');
SQL

psql -X -v ON_ERROR_STOP=1 -d examos_policy_activation_test \
    -f "$ROOT/server/migrations/048_block_legacy_exam_policy_activation.sql" >/dev/null
psql -X -v ON_ERROR_STOP=1 -d examos_policy_activation_test \
    -f "$ROOT/server/migrations/048_block_legacy_exam_policy_activation.sql" >/dev/null

preserved="$(psql -X -At -v ON_ERROR_STOP=1 -d examos_policy_activation_test \
    -c "SELECT count(*) FROM examos_exam_policies WHERE status='ACTIVE' AND signature='legacy-hmac'")"
[[ "$preserved" == "1" ]] || {
    echo "Migration did not preserve the historical active record." >&2
    exit 1
}

if psql -X -q -v ON_ERROR_STOP=1 -d examos_policy_activation_test \
    -c "INSERT INTO examos_exam_policies (exam_id,policy_version,exam_url,signature,status) VALUES ('new',1,'https://exam.example.test','legacy-hmac','ACTIVE')" >/dev/null 2>&1; then
    echo "Direct ACTIVE insert was accepted." >&2
    exit 1
fi
if psql -X -q -v ON_ERROR_STOP=1 -d examos_policy_activation_test \
    -c "INSERT INTO examos_exam_policies (exam_id,policy_version,exam_url,signature,status) VALUES ('new',1,'https://exam.example.test','legacy-hmac','SUPERSEDED')" >/dev/null 2>&1; then
    echo "Legacy policy creation was accepted." >&2
    exit 1
fi
if psql -X -q -v ON_ERROR_STOP=1 -d examos_policy_activation_test \
    -c "UPDATE examos_exam_policies SET status='ACTIVE' WHERE exam_id='exam-history' AND policy_version=2" >/dev/null 2>&1; then
    echo "Direct activation of a superseded policy was accepted." >&2
    exit 1
fi
if psql -X -q -v ON_ERROR_STOP=1 -d examos_policy_activation_test \
    -c "UPDATE examos_exam_policies SET status='ROLLBACK' WHERE exam_id='exam-history' AND policy_version=1" >/dev/null 2>&1; then
    echo "Direct rollback-state activation was accepted." >&2
    exit 1
fi
if psql -X -q -v ON_ERROR_STOP=1 -d examos_policy_activation_test \
    -c "UPDATE examos_exam_policies SET signature='tampered' WHERE exam_id='exam-history' AND policy_version=1" >/dev/null 2>&1; then
    echo "Mutation of historical active policy evidence was accepted." >&2
    exit 1
fi
if psql -X -q -v ON_ERROR_STOP=1 -d examos_policy_activation_test \
    -c "DELETE FROM examos_exam_policies WHERE exam_id='exam-history' AND policy_version=1" >/dev/null 2>&1; then
    echo "Deletion of a historical active policy was accepted." >&2
    exit 1
fi

psql -X -v ON_ERROR_STOP=1 -d examos_policy_activation_test \
    -c "UPDATE examos_exam_policies SET status='SUPERSEDED' WHERE exam_id='exam-history' AND policy_version=1" >/dev/null
if psql -X -q -v ON_ERROR_STOP=1 -d examos_policy_activation_test \
    -c "UPDATE examos_exam_policies SET signature='tampered' WHERE exam_id='exam-history' AND policy_version=1" >/dev/null 2>&1; then
    echo "Mutation of deactivated historical policy evidence was accepted." >&2
    exit 1
fi
if psql -X -q -v ON_ERROR_STOP=1 -d examos_policy_activation_test \
    -c "UPDATE examos_exam_policies SET status='ACTIVE' WHERE exam_id='exam-history' AND policy_version=1" >/dev/null 2>&1; then
    echo "A deactivated historical policy could be reactivated." >&2
    exit 1
fi
if psql -X -q -v ON_ERROR_STOP=1 -d examos_policy_activation_test \
    -c "DELETE FROM examos_exam_policies WHERE exam_id='exam-history' AND policy_version=2" >/dev/null 2>&1; then
    echo "Deletion of a superseded policy was accepted." >&2
    exit 1
fi

echo "Legacy policy activation guard and historical-record preservation passed."
