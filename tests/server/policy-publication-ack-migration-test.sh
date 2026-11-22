#!/usr/bin/env bash
set -euo pipefail

if [[ "$(id -u)" -eq 0 ]]; then
    echo "Run this test as an unprivileged user; PostgreSQL refuses initdb as root." >&2
    exit 1
fi

for tool in pg_config psql createdb; do command -v "$tool" >/dev/null || exit 1; done
PG_BIN="$(pg_config --bindir)"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/examos-policy-ack-test.XXXXXX")"
PORT="$((20000 + RANDOM % 20000))"

cleanup() {
    "$PG_BIN/pg_ctl" -D "$TMP_DIR/data" -m immediate stop >/dev/null 2>&1 || true
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

"$PG_BIN/initdb" -D "$TMP_DIR/data" --auth-local=trust --auth-host=trust --no-instructions >/dev/null
"$PG_BIN/pg_ctl" -D "$TMP_DIR/data" -o "-p $PORT -k $TMP_DIR" -l "$TMP_DIR/postgres.log" start >/dev/null
export PGHOST="$TMP_DIR" PGPORT="$PORT" PGUSER="$(id -un)"
createdb examos_policy_ack_test

psql -X -v ON_ERROR_STOP=1 -d examos_policy_ack_test <<'SQL'
CREATE TABLE examos_schema_migrations (
    component TEXT NOT NULL,
    version INTEGER NOT NULL,
    PRIMARY KEY (component, version)
);
SQL

psql -X -v ON_ERROR_STOP=1 -d examos_policy_ack_test \
    -f "$ROOT/server/migrations/049_policy_publication_acknowledgement.sql" >/dev/null

psql -X -v ON_ERROR_STOP=1 -d examos_policy_ack_test <<'SQL'
INSERT INTO examos_policy_signing_keys
(key_id,institution_id,public_key_pem,public_key_fingerprint,algorithm,status,valid_from)
VALUES
('polkey-1','inst-1','public-key-placeholder','sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
 'ed25519','active',clock_timestamp());

INSERT INTO examos_published_policies
(policy_release_id,exam_id,institution_id,policy_version,canonical_payload,
 canonical_payload_sha256,canonical_version,signing_key_id,signature_base64,state)
VALUES
('policy-rel-1','exam-1','inst-1',1,'{"policyVersion":1}',
 'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
 'RFC8785','polkey-1','placeholder-signature','PUBLISHED');

INSERT INTO examos_policy_enforcement_challenges
(challenge_id,exam_id,institution_id,device_id,policy_release_id,policy_version,
 policy_digest,nonce_sha256,state,expires_at)
VALUES
('challenge-1','exam-1','inst-1','device-1','policy-rel-1',1,
 'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
 'pending',clock_timestamp()+interval '5 minutes');
SQL

if psql -X -q -v ON_ERROR_STOP=1 -d examos_policy_ack_test \
    -c "INSERT INTO examos_policy_device_acknowledgements (acknowledgement_id,challenge_id,exam_id,institution_id,device_id,policy_release_id,policy_version,policy_digest,enforcement_status,attestation_id,signature_base64) VALUES ('ack-1','challenge-1','exam-2','inst-1','device-1','policy-rel-1',1,'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb','ENFORCED','attest-1','invalid')" >/dev/null 2>&1; then
    echo "ACK insert unexpectedly succeeded as PUBLIC; no trigger or constraint blocked mismatches." >&2
    exit 1
fi

echo "Policy publication and acknowledgement migration guard passed."
