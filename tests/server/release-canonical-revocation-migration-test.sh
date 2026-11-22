#!/usr/bin/env bash
set -euo pipefail

if [[ "$(id -u)" -eq 0 ]]; then
    echo "Run this test as an unprivileged user; PostgreSQL refuses initdb as root." >&2
    exit 1
fi

for tool in pg_config psql createdb; do command -v "$tool" >/dev/null || exit 1; done
PG_BIN="$(pg_config --bindir)"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/examos-release-trust-test.XXXXXX")"
PORT="$((20000 + RANDOM % 20000))"

cleanup() {
    "$PG_BIN/pg_ctl" -D "$TMP_DIR/data" -m immediate stop >/dev/null 2>&1 || true
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

"$PG_BIN/initdb" -D "$TMP_DIR/data" --auth-local=trust --auth-host=trust --no-instructions >/dev/null
"$PG_BIN/pg_ctl" -D "$TMP_DIR/data" -o "-p $PORT -k $TMP_DIR" -l "$TMP_DIR/postgres.log" start >/dev/null
export PGHOST="$TMP_DIR" PGPORT="$PORT" PGUSER="$(id -un)"
createdb examos_release_trust_test

psql -X -v ON_ERROR_STOP=1 -d examos_release_trust_test <<'SQL'
CREATE TABLE examos_schema_migrations (
    component TEXT NOT NULL,
    version INTEGER NOT NULL,
    PRIMARY KEY (component, version)
);
CREATE TABLE os_releases (
    id VARCHAR(64) PRIMARY KEY,
    release_id VARCHAR(64),
    status VARCHAR(32),
    revoked_at BIGINT,
    manifest_digest VARCHAR(128),
    signing_key_id VARCHAR(64)
);
CREATE TABLE os_release_manifests (
    release_id VARCHAR(64) PRIMARY KEY,
    canonical_payload TEXT,
    canonical_payload_sha256 VARCHAR(128),
    canonical_version VARCHAR(32),
    signing_key_id VARCHAR(64)
);
CREATE TABLE os_release_signing_keys (
    key_id VARCHAR(64) PRIMARY KEY,
    revoked_at BIGINT
);
SQL

psql -X -v ON_ERROR_STOP=1 -d examos_release_trust_test \
    -f "$ROOT/server/migrations/050_release_canonical_revocation_trust.sql" >/dev/null

psql -X -v ON_ERROR_STOP=1 -d examos_release_trust_test <<'SQL'
INSERT INTO os_releases (id,release_id,status,manifest_digest)
VALUES ('rel-1','ExamOS-Test','draft','sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
INSERT INTO os_release_revocations
(release_id,manifest_digest,authority_key_id,authority_key_fingerprint,signature_base64,revoked_at)
VALUES ('rel-1','sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        'authority-1','sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
        'invalid','1');
SQL

count="$(psql -X -At -v ON_ERROR_STOP=1 -d examos_release_trust_test \
    -c "SELECT count(*) FROM os_release_revocations")"
[[ "$count" == "1" ]] || exit 1

echo "Release canonical payload and revocation migration guard passed."
