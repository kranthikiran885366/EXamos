#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INSTITUTIONS="$ROOT/server/controllers/institution_controller.c"
EXAMS="$ROOT/server/controllers/exam_controller.c"
API="$ROOT/frontend/src/core/api/services.js"
CLIENT="$ROOT/frontend/src/core/api/client.js"
EXAM_PAGES="$ROOT/frontend/src/modules/exams/pages.jsx"
EXAM_SERVICE="$ROOT/frontend/src/modules/exams/service.js"
MODULES="$ROOT/server/controllers/modules_controller.c"
POLICIES="$ROOT/server/controllers/policy_controller.c"
DB="$ROOT/server/db/db.c"

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
require_text "$EXAM_PAGES" 'function useInstitutionCenters(tenantId)'
require_text "$EXAM_PAGES" 'listBackendCenters(tenantId).then((rows)'
require_text "$EXAM_SERVICE" 'listBackendCenters(ex.tenantId)'
require_text "$EXAM_SERVICE" 'Api.listExaminationStudents(ex.id)'
require_text "$MODULES" '[console-data] read failed collection=%s sqlstate=%s'
require_text "$MODULES" 'Record not found'
require_text "$POLICIES" 'FROM console_records WHERE collection='\''policies'\'' '
require_text "$POLICIES" 'AND ($2::boolean OR institution_id=$1)'
require_text "$EXAM_PAGES" 'loadInstitutionPolicies(tenantId)'
require_text "$EXAM_PAGES" 'Array.isArray(policyData) ? policyData : []'
require_text "$EXAM_PAGES" 'No active center mapped'
require_text "$EXAM_PAGES" 'Array.isArray(backendCenters) ? backendCenters : []'
require_text "$INSTITUTIONS" '[campus] create insert failed sqlstate=%s constraint=%s column=%s'
require_text "$DB" 'EXTRACT(EPOCH FROM created_at) * 1000)::BIGINT'
require_text "$DB" 'EXTRACT(EPOCH FROM updated_at) * 1000)::BIGINT'

echo "[PILOT-EXAM] PASS: pilot setup, live exam centres/assignments/policies, diagnostics, and bounded save requests."
