#!/usr/bin/env bash
set -euo pipefail

WORKSPACE="$(cd "$(dirname "$0")/../.." && pwd)"
ARTIFACT_DIR="${EXAMOS_P0_ARTIFACT_DIR:?Run scripts/p0.sh or provide an isolated P0 run directory}"
source "$WORKSPACE/scripts/examos-lib.sh"
examos_p0_validate_run_dir "$WORKSPACE" "$ARTIFACT_DIR" || {
    echo "[P0-ADMIN-AUTH] FATAL: evidence path is not an isolated P0 run directory." >&2
    exit 2
}

RESULT="$ARTIFACT_DIR/admin-auth-security-result.json"
LOG="$ARTIFACT_DIR/admin-auth-security.log"
for output in "$RESULT" "$LOG"; do
    if [ -e "$output" ] || [ -L "$output" ]; then
        echo "[P0-ADMIN-AUTH] FATAL: refusing to overwrite evidence: $output" >&2
        exit 2
    fi
done

SOURCE_COMMIT="$(git -C "$WORKSPACE" rev-parse HEAD)"
SOURCE_STATE="$(examos_p0_source_status "$WORKSPACE")"
[ -z "$SOURCE_STATE" ] || {
    echo "[P0-ADMIN-AUTH] BLOCKED: source tree is dirty." >&2
    exit 2
}
TMP_DIR="$(mktemp -d "${TMPDIR:-/var/tmp}/examos-p0-admin-auth.XXXXXX")"
trap 'rm -rf -- "$TMP_DIR"' EXIT
STATUS="PASS"
if ! "${CC:-cc}" -std=c11 -O2 -Wall -Wextra -Werror \
    -Wformat=2 -Werror=format-security -D_FORTIFY_SOURCE=2 \
    -fstack-protector-strong \
    "$WORKSPACE/tests/server/password-hash-test.c" \
    "$WORKSPACE/server/admin/config_manager.c" \
    "$WORKSPACE/server/admin/admin_dashboard.c" -lcrypto -lpq \
    -o "$TMP_DIR/admin-auth-test" >"$LOG" 2>&1 ||
    ! "$TMP_DIR/admin-auth-test" >>"$LOG" 2>&1; then
    STATUS="FAIL"
fi
[ "$(git -C "$WORKSPACE" rev-parse HEAD)" = "$SOURCE_COMMIT" ] &&
    [ -z "$(examos_p0_source_status "$WORKSPACE")" ] || STATUS="FAIL"
cat > "$RESULT" <<EOF
{
  "schema": "examos.p0.admin-auth-security.v1",
  "phase": "P0",
  "check": "admin_auth_security",
  "status": "$STATUS",
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "source_commit": "$SOURCE_COMMIT",
  "pbkdf2_verification": "$STATUS",
  "missing_legacy_and_unprovisioned_credentials_fail_closed": "$STATUS",
  "unsafe_config_permissions_rejected": "$STATUS"
}
EOF
if [ "$STATUS" = PASS ]; then
    echo "[P0-ADMIN-AUTH] PBKDF2 authentication and fail-closed config checks: PASS"
else
    echo "[P0-ADMIN-AUTH] credential security regression: FAIL" >&2
    cat "$LOG" >&2 || true
    exit 1
fi
