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
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/examos-challenge-test.XXXXXX")"
PORT="$((20000 + RANDOM % 20000))"

cleanup() {
    "$PG_BIN/pg_ctl" -D "$TMP_DIR/data" -m immediate stop >/dev/null 2>&1 || true
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

"$PG_BIN/initdb" -D "$TMP_DIR/data" --auth-local=trust --auth-host=reject \
    --no-instructions >/dev/null
"$PG_BIN/pg_ctl" -D "$TMP_DIR/data" \
    -o "-p $PORT -k $TMP_DIR -c listen_addresses=''" \
    -l "$TMP_DIR/postgres.log" start >/dev/null
export PGHOST="$TMP_DIR" PGPORT="$PORT" PGUSER="$(id -un)"
export PGOPTIONS='-c client_min_messages=warning'
createdb --maintenance-db=postgres examos_challenge_test
export PGDATABASE=examos_challenge_test
export EXAMOS_CHALLENGE_TEST_ISOLATED=1

psql -X -v ON_ERROR_STOP=1 <<'SQL'
CREATE EXTENSION pgcrypto;
CREATE TABLE examos_schema_migrations (
    component TEXT NOT NULL,
    version INTEGER NOT NULL,
    PRIMARY KEY (component, version)
);
CREATE TABLE devices (
    id VARCHAR(63) PRIMARY KEY,
    institution_id VARCHAR(63) NOT NULL,
    status VARCHAR(32) NOT NULL
);
CREATE TABLE device_registrations (
    id VARCHAR(63) PRIMARY KEY,
    device_id VARCHAR(63) NOT NULL,
    institution_id VARCHAR(63) NOT NULL,
    decision VARCHAR(32) NOT NULL
);
CREATE TABLE device_trust_policies (
    id VARCHAR(63) PRIMARY KEY,
    institution_id VARCHAR(63) NOT NULL,
    status VARCHAR(32) NOT NULL
);
CREATE TABLE exam_sessions (
    id VARCHAR(64) PRIMARY KEY,
    institution_id VARCHAR(64) NOT NULL,
    device_id VARCHAR(64) NOT NULL,
    status VARCHAR(32) NOT NULL
);
CREATE TABLE candidate_exam_checkins (
    exam_session_id VARCHAR(64) PRIMARY KEY,
    institution_id VARCHAR(64) NOT NULL,
    status VARCHAR(32) NOT NULL,
    expires_at BIGINT NOT NULL
);
SQL

for migration in \
    "$ROOT/server/migrations/010_attestation_challenge_state.sql" \
    "$ROOT/server/migrations/011_attestation_revocations.sql"; do
    psql -X -v ON_ERROR_STOP=1 -f "$migration" >/dev/null
done

psql -X -v ON_ERROR_STOP=1 <<'SQL'
INSERT INTO examos_attestation_challenges
    (attestation_id, session_id, device_id, release_id, nonce_sha256,
     state, created_at, expires_at)
VALUES
    ('attest-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'sess_legacy', 'dev_legacy',
     'rel_legacy', repeat('a', 64), 'PENDING',
     clock_timestamp(), clock_timestamp() + interval '30 seconds');
SQL

psql -X -v ON_ERROR_STOP=1 \
    -f "$ROOT/server/migrations/042_challenge_lifecycle_enhancements.sql" >/dev/null

# The 042 migration is safe to rerun, including its legacy-row handling.
psql -X -v ON_ERROR_STOP=1 \
    -f "$ROOT/server/migrations/042_challenge_lifecycle_enhancements.sql" >/dev/null

marker_count="$(psql -X -At -v ON_ERROR_STOP=1 \
    -c "SELECT COUNT(*) FROM examos_schema_migrations WHERE component='device_fleet' AND version=42")"
[[ "$marker_count" == "1" ]] || {
    echo "Challenge lifecycle migration was not recorded exactly once." >&2
    exit 1
}
legacy_count="$(psql -X -At -v ON_ERROR_STOP=1 \
    -c "SELECT COUNT(*) FROM examos_attestation_challenges WHERE attestation_id='attest-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' AND institution_id='legacy' AND purpose='re_attestation' AND created_by='legacy' AND state='STALE'")"
[[ "$legacy_count" == "1" ]] || {
    echo "Legacy unbound challenge was not quarantined." >&2
    exit 1
}

"${CC:-cc}" -std=c11 -Wall -Wextra -Werror \
    -I"$(pg_config --includedir)" \
    "$ROOT/tests/server/challenge_lifecycle_test.c" \
    -o "$TMP_DIR/challenge_lifecycle_test" -lpq -lcrypto -lpthread
"$TMP_DIR/challenge_lifecycle_test"
