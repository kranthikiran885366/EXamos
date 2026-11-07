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
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/examos-device-policy-test.XXXXXX")"
PORT="$((20000 + RANDOM % 20000))"

cleanup() {
    "$PG_BIN/pg_ctl" -D "$TMP_DIR/data" -m immediate stop >/dev/null 2>&1 || true
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

"$PG_BIN/initdb" -D "$TMP_DIR/data" --auth-local=trust --auth-host=trust --no-instructions >/dev/null
"$PG_BIN/pg_ctl" -D "$TMP_DIR/data" -o "-p $PORT -k $TMP_DIR" -l "$TMP_DIR/postgres.log" start >/dev/null
export PGHOST="$TMP_DIR" PGPORT="$PORT" PGUSER="$(id -un)"
createdb examos_device_policy_test

psql -X -v ON_ERROR_STOP=1 -d examos_device_policy_test <<'SQL'
CREATE TABLE device_trust_policies (id VARCHAR(64) PRIMARY KEY);
INSERT INTO device_trust_policies (id) VALUES ('legacy_draft');
SQL

psql -X -v ON_ERROR_STOP=1 -d examos_device_policy_test \
    -f "$ROOT/server/migrations/034_device_trust_policy_approvals.sql" >/dev/null
psql -X -v ON_ERROR_STOP=1 -d examos_device_policy_test \
    -f "$ROOT/server/migrations/034_device_trust_policy_approvals.sql" >/dev/null

legacy_creator="$(psql -X -At -v ON_ERROR_STOP=1 -d examos_device_policy_test \
    -c "SELECT created_by FROM device_trust_policies WHERE id='legacy_draft'")"
[[ "$legacy_creator" == "" ]] || {
    echo "Legacy policy creator should remain explicitly unverified." >&2
    exit 1
}

psql -X -v ON_ERROR_STOP=1 -d examos_device_policy_test \
    -c "INSERT INTO device_trust_policies (id, created_by) VALUES ('new_draft', 'creator-test')" >/dev/null
creator="$(psql -X -At -v ON_ERROR_STOP=1 -d examos_device_policy_test \
    -c "SELECT created_by FROM device_trust_policies WHERE id='new_draft'")"
[[ "$creator" == "creator-test" ]] || {
    echo "Creator identity was not persisted." >&2
    exit 1
}

echo "Device trust policy creator migration and idempotency checks passed."
