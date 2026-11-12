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
export PGOPTIONS='-c client_min_messages=warning'
createdb examos_release_trust_test

psql -X -v ON_ERROR_STOP=1 -d examos_release_trust_test <<'SQL'
CREATE TABLE examos_schema_migrations (
    component TEXT NOT NULL,
    version INTEGER NOT NULL,
    PRIMARY KEY (component, version)
);
CREATE TABLE devices (id VARCHAR(64) PRIMARY KEY);
CREATE TABLE os_release_signing_keys (
    id VARCHAR(64) PRIMARY KEY,
    key_id VARCHAR(64) UNIQUE NOT NULL,
    key_name VARCHAR(128) NOT NULL DEFAULT '',
    public_key_pem TEXT NOT NULL,
    key_fingerprint VARCHAR(128) NOT NULL,
    key_type VARCHAR(32) NOT NULL,
    status VARCHAR(32) NOT NULL,
    created_at BIGINT NOT NULL DEFAULT 0
);
CREATE TABLE os_releases (
    id VARCHAR(64) PRIMARY KEY,
    release_id VARCHAR(64) UNIQUE NOT NULL,
    version VARCHAR(64) NOT NULL DEFAULT '',
    source_commit VARCHAR(64) DEFAULT '',
    build_config TEXT DEFAULT '',
    toolchain_version VARCHAR(64) DEFAULT '',
    kernel_version VARCHAR(64) NOT NULL DEFAULT '',
    minimum_supported_version VARCHAR(64) DEFAULT '',
    policy_version VARCHAR(64) DEFAULT '',
    status VARCHAR(32) NOT NULL,
    signing_key_id VARCHAR(64),
    manifest_digest VARCHAR(128) DEFAULT '',
    manifest_signature TEXT DEFAULT '',
    rollback_permitted BOOLEAN NOT NULL DEFAULT FALSE,
    created_by VARCHAR(64) DEFAULT '',
    approved_by VARCHAR(64) DEFAULT '',
    approved_at BIGINT,
    created_at BIGINT NOT NULL DEFAULT 0,
    updated_at BIGINT NOT NULL DEFAULT 0
);
CREATE TABLE os_release_artifacts (
    id VARCHAR(64) PRIMARY KEY,
    release_id VARCHAR(64) NOT NULL REFERENCES os_releases(id),
    artifact_name VARCHAR(64) NOT NULL,
    artifact_type VARCHAR(32) NOT NULL,
    sha256_digest VARCHAR(128) NOT NULL,
    size_bytes BIGINT DEFAULT 0,
    download_url TEXT DEFAULT '',
    signature TEXT DEFAULT ''
);
CREATE TABLE os_release_manifests (
    id VARCHAR(64) PRIMARY KEY,
    release_id VARCHAR(64) UNIQUE NOT NULL REFERENCES os_releases(id),
    manifest_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    manifest_digest VARCHAR(128) NOT NULL,
    signature_algorithm VARCHAR(32) DEFAULT '',
    signature_value TEXT NOT NULL,
    verified BOOLEAN NOT NULL DEFAULT FALSE,
    created_at BIGINT NOT NULL DEFAULT 0
);
CREATE TABLE os_release_approvals (
    id VARCHAR(64) PRIMARY KEY,
    release_id VARCHAR(64) NOT NULL REFERENCES os_releases(id),
    reviewer_id VARCHAR(64) NOT NULL,
    decision VARCHAR(32) NOT NULL,
    notes TEXT DEFAULT '',
    created_at BIGINT NOT NULL DEFAULT 0
);
CREATE TABLE os_deployment_assignments (id VARCHAR(64) PRIMARY KEY);
CREATE TABLE os_deployment_groups (id VARCHAR(64) PRIMARY KEY);
CREATE TABLE device_os_releases (
    id VARCHAR(64) PRIMARY KEY,
    release_version VARCHAR(64) UNIQUE NOT NULL,
    release_name VARCHAR(128) NOT NULL DEFAULT '',
    signing_key_id VARCHAR(64) NOT NULL,
    status VARCHAR(32) NOT NULL CHECK (status IN ('draft', 'active', 'deprecated', 'revoked')),
    min_supported BOOLEAN NOT NULL DEFAULT TRUE,
    created_at BIGINT NOT NULL DEFAULT 0,
    updated_at BIGINT NOT NULL DEFAULT 0
);
INSERT INTO os_release_signing_keys
    (id, key_id, public_key_pem, key_fingerprint, key_type, status)
VALUES
    ('oskey_prod_root_01', 'examos-prod-signing-key-v2',
     '-----BEGIN PUBLIC KEY-----' || chr(10) || 'MIIB...truncated...' || chr(10) || '-----END PUBLIC KEY-----',
     'sha256:d8a9e0f1c2b3a4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9',
     'production', 'active'),
    ('valid-key', 'valid-key-id', 'PUBLIC KEY', 'sha256:valid', 'production', 'active');
INSERT INTO os_releases
    (id, release_id, version, status, signing_key_id, manifest_digest, manifest_signature)
VALUES
    ('osrel_examos_2_0_base', 'ExamOS 2.0', '2.0.0', 'active',
     'examos-prod-signing-key-v2',
     'sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
     'MIIEYgYJKoZIhvcNAQcCo...='),
    ('other-release', 'OtherOS 1.0', '1.0.0', 'active', 'valid-key-id',
     'sha256:verified', 'verified-signature');
INSERT INTO os_release_artifacts
    (id, release_id, artifact_name, artifact_type, sha256_digest, signature)
VALUES
    ('rootfs-2', 'osrel_examos_2_0_base', 'rootfs', 'image', 'sha256:placeholder', 'SIG_PLACEHOLDER'),
    ('rootfs-other', 'other-release', 'rootfs', 'image', 'sha256:verified', 'verified-signature');
INSERT INTO os_release_manifests
    (id, release_id, manifest_json, manifest_digest, signature_value, verified)
VALUES
    ('manifest-2', 'osrel_examos_2_0_base', '{}'::jsonb,
     'sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
     'MIIEYgYJKoZIhvcNAQcCo...=', TRUE),
    ('manifest-other', 'other-release', '{"complete":true}'::jsonb,
     'sha256:verified', 'verified-signature', TRUE);
INSERT INTO device_os_releases
    (id, release_version, release_name, signing_key_id, status)
VALUES
    ('rel_examos_2.0', 'ExamOS 2.0', 'ExamOS 2.0', 'examos-prod-key-1', 'active'),
    ('other-device-release', 'OtherOS 1.0', 'OtherOS', 'other-key', 'active');
SQL

psql -X -v ON_ERROR_STOP=1 -d examos_release_trust_test \
    -f "$ROOT/server/migrations/041_release_engineering_pipeline.sql" >/dev/null
psql -X -v ON_ERROR_STOP=1 -d examos_release_trust_test \
    -f "$ROOT/server/migrations/041_release_engineering_pipeline.sql" >/dev/null

placeholder_state="$(psql -X -At -v ON_ERROR_STOP=1 -d examos_release_trust_test \
    -c "SELECT r.status||'|'||r.trust_status||'|'||r.verification_state||'|'||k.status||'|'||m.verified::text||'|'||m.signature_verified::text||'|'||d.status FROM os_releases r JOIN os_release_manifests m ON m.release_id=r.id JOIN os_release_signing_keys k ON k.key_id=r.signing_key_id JOIN device_os_releases d ON d.release_version=r.release_id WHERE r.id='osrel_examos_2_0_base'")"
[[ "$placeholder_state" == "active|unverified|not_verified|placeholder|false|false|deprecated" ]] || {
    echo "Placeholder release trust was not fully restricted: $placeholder_state" >&2
    exit 1
}

artifact_state="$(psql -X -At -v ON_ERROR_STOP=1 -d examos_release_trust_test \
    -c "SELECT (SELECT verification_note FROM os_release_artifacts WHERE id='rootfs-2')||'|'||(SELECT verification_note FROM os_release_artifacts WHERE id='rootfs-other')")"
[[ "$artifact_state" == "Placeholder artifact seeded by migration 023; no storage object or build provenance exists.|" ]] || {
    echo "Artifact quarantine changed the wrong release or missed its placeholder: $artifact_state" >&2
    exit 1
}

unrelated_state="$(psql -X -At -v ON_ERROR_STOP=1 -d examos_release_trust_test \
    -c "SELECT r.status||'|'||r.trust_status||'|'||m.verified::text||'|'||k.status||'|'||d.status FROM os_releases r JOIN os_release_manifests m ON m.release_id=r.id JOIN os_release_signing_keys k ON k.key_id=r.signing_key_id JOIN device_os_releases d ON d.release_version=r.release_id WHERE r.id='other-release'")"
[[ "$unrelated_state" == "active|unverified|true|active|active" ]] || {
    echo "Migration changed unrelated release trust or operational status: $unrelated_state" >&2
    exit 1
}

audit_count="$(psql -X -At -v ON_ERROR_STOP=1 -d examos_release_trust_test \
    -c "SELECT COUNT(*) FROM os_release_audit_events WHERE id='osrevaudit_041_quarantine_base'")"
[[ "$audit_count" == "1" ]] || {
    echo "Placeholder release quarantine audit was not recorded exactly once: $audit_count" >&2
    exit 1
}
if psql -X -q -v ON_ERROR_STOP=1 -d examos_release_trust_test \
    -c "UPDATE os_release_audit_events SET detail='mutated' WHERE id='osrevaudit_041_quarantine_base'" >/dev/null 2>&1; then
    echo "OS release audit history accepted an update." >&2
    exit 1
fi

marker_count="$(psql -X -At -v ON_ERROR_STOP=1 -d examos_release_trust_test \
    -c "SELECT COUNT(*) FROM examos_schema_migrations WHERE component='os_releases' AND version=41")"
[[ "$marker_count" == "1" ]] || {
    echo "Release engineering migration version marker was not recorded exactly once." >&2
    exit 1
}

echo "Release pipeline schema, placeholder quarantine, trust separation, and idempotency checks passed."
