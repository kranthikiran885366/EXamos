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
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/examos-application-url-test.XXXXXX")"
PORT="$((20000 + RANDOM % 20000))"

cleanup() {
    "$PG_BIN/pg_ctl" -D "$TMP_DIR/data" -m immediate stop >/dev/null 2>&1 || true
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

"$PG_BIN/initdb" -D "$TMP_DIR/data" --auth-local=trust --auth-host=trust --no-instructions >/dev/null
"$PG_BIN/pg_ctl" -D "$TMP_DIR/data" -o "-p $PORT -k $TMP_DIR" -l "$TMP_DIR/postgres.log" start >/dev/null
export PGHOST="$TMP_DIR" PGPORT="$PORT" PGUSER="$(id -un)"
createdb examos_application_url_test

psql -X -v ON_ERROR_STOP=1 -d examos_application_url_test <<'SQL'
CREATE TABLE examos_schema_migrations (
    component TEXT NOT NULL,
    version INTEGER NOT NULL,
    PRIMARY KEY (component, version)
);
CREATE TABLE institution_applications (
    id VARCHAR(64) PRIMARY KEY
);
SQL

psql -X -v ON_ERROR_STOP=1 -d examos_application_url_test \
    -f "$ROOT/server/migrations/037_institution_application_assessment_url.sql" >/dev/null
psql -X -v ON_ERROR_STOP=1 -d examos_application_url_test \
    -f "$ROOT/server/migrations/037_institution_application_assessment_url.sql" >/dev/null
psql -X -v ON_ERROR_STOP=1 -d examos_application_url_test \
    -f "$ROOT/server/migrations/038_institution_application_review_checklist.sql" >/dev/null
psql -X -v ON_ERROR_STOP=1 -d examos_application_url_test \
    -f "$ROOT/server/migrations/038_institution_application_review_checklist.sql" >/dev/null
psql -X -v ON_ERROR_STOP=1 -d examos_application_url_test \
    -c "INSERT INTO institution_applications (id, target_exam_url, review_checklist) VALUES ('app-test', 'https://assessment.example.edu/exam', '{\"identity\":true,\"domain\":true,\"accreditation\":true,\"representative\":true,\"datacenter\":true}')" >/dev/null

saved_fields="$(psql -X -At -F '|' -v ON_ERROR_STOP=1 -d examos_application_url_test \
    -c "SELECT target_exam_url, review_checklist->>'identity', review_checklist->>'domain', review_checklist->>'accreditation', review_checklist->>'representative', review_checklist->>'datacenter' FROM institution_applications WHERE id='app-test'")"
[[ "$saved_fields" == "https://assessment.example.edu/exam|true|true|true|true|true" ]] || {
    echo "The application URL or verification checklist was not persisted." >&2
    exit 1
}

marker_count="$(psql -X -At -v ON_ERROR_STOP=1 -d examos_application_url_test \
    -c "SELECT COUNT(*) FROM examos_schema_migrations WHERE component='institutions' AND version IN (2,3)")"
[[ "$marker_count" == "2" ]] || {
    echo "Institution migration markers were not recorded exactly once." >&2
    exit 1
}

echo "Institution assessment URL migration and persistence checks passed."
