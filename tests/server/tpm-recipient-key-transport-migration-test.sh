#!/usr/bin/env bash
set -euo pipefail

if [[ "$(id -u)" -eq 0 ]]; then
    echo "Run this test as an unprivileged user; PostgreSQL refuses initdb as root." >&2
    exit 1
fi

for tool in pg_config psql createdb; do command -v "$tool" >/dev/null || exit 1; done
PG_BIN="$(pg_config --bindir)"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/examos-tpm-wrap-test.XXXXXX")"
PORT="$((20000 + RANDOM % 20000))"

cleanup() {
    "$PG_BIN/pg_ctl" -D "$TMP_DIR/data" -m immediate stop >/dev/null 2>&1 || true
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

"$PG_BIN/initdb" -D "$TMP_DIR/data" --auth-local=trust --auth-host=trust --no-instructions >/dev/null
"$PG_BIN/pg_ctl" -D "$TMP_DIR/data" -o "-p $PORT -k $TMP_DIR" -l "$TMP_DIR/postgres.log" start >/dev/null
export PGHOST="$TMP_DIR" PGPORT="$PORT" PGUSER="$(id -un)"
createdb examos_tpm_wrap_test

psql -X -v ON_ERROR_STOP=1 -d examos_tpm_wrap_test <<'SQL'
CREATE TABLE examos_schema_migrations (
    component TEXT NOT NULL,
    version INTEGER NOT NULL,
    PRIMARY KEY (component, version)
);
CREATE TABLE examos_attestation_challenges (
    attestation_id VARCHAR(63) PRIMARY KEY
);
SQL
psql -X -v ON_ERROR_STOP=1 -d examos_tpm_wrap_test \
    -f "$ROOT/server/migrations/051_tpm_recipient_key_transport.sql" >/dev/null

if psql -X -q -v ON_ERROR_STOP=1 -d examos_tpm_wrap_test \
    -c "INSERT INTO examos_exam_key_transports (transport_id,attestation_id,session_id,candidate_id,device_id,recipient_fingerprint,algorithm,envelope_sha256,envelope_base64,state) VALUES ('ket_1','attest-1','session-1','candidate-1','device-1','aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','rsa-oaep-sha256','sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb','envelope','wrapped')" >/dev/null 2>&1; then
    echo "Test setup unexpectedly accepted an invalid transport row." >&2
    exit 1
fi

echo "TPM recipient transport migration guard passed."
