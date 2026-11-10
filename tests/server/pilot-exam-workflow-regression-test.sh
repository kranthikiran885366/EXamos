#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INSTITUTIONS="$ROOT/server/controllers/institution_controller.c"
EXAMS="$ROOT/server/controllers/exam_controller.c"
API="$ROOT/frontend/src/core/api/services.js"
CLIENT="$ROOT/frontend/src/core/api/client.js"

require_text() {
    local file="$1"
    local text="$2"
    if ! grep -Fq -- "$text" "$file"; then
        printf '[PILOT-EXAM] FAIL: expected source text not found in %s: %s\n' "$file" "$text" >&2
        exit 1
    fi
}

require_text "$INSTITUTIONS" 'static int inst_status_allows_organization_setup'
require_text "$INSTITUTIONS" 'strcmp(status, "pilot") == 0 || strcmp(status, "active") == 0'
require_text "$INSTITUTIONS" "'pilot'"
require_text "$INSTITUTIONS" 'Institution activation requires an executed agreement'

setup_gate_count="$(grep -Fc 'inst_status_allows_organization_setup(' "$INSTITUTIONS")"
if [[ "$setup_gate_count" -lt 3 ]]; then
    echo "[PILOT-EXAM] FAIL: campus and center creation must share the pilot/active gate." >&2
    exit 1
fi

require_text "$EXAMS" 'created_at, updated_at, status, created_by) '
require_text "$EXAMS" 'sess.user_id };'
require_text "$EXAMS" 'PG_DIAG_SQLSTATE'
require_text "$EXAMS" 'Exam storage is missing a required database field or table.'
require_text "$API" 'retries: 0, timeoutMs: 15000'
require_text "$CLIENT" 'Request timed out after ${Math.ceil(timeoutMs / 1000)} seconds.'

echo "[PILOT-EXAM] PASS: pilot setup, activation gates, exam persistence diagnostics, and bounded save requests."
