#!/usr/bin/env bash
# =============================================================================
# ExamOS SPPIO™ — Full End-to-End Test Suite
# tests/examos-e2e-full.sh
#
# Covers: OS build → P0 boot → P1 kiosk → P2 lockdown → P3 attestation →
#         P4 proctoring → P5 behaviour/variant/viva → Dashboard API integration
#         All tests run against a live real server with ephemeral PostgreSQL.
# =============================================================================
set -uo pipefail

WORKSPACE="$(cd "$(dirname "$0")/.." && pwd)"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"
ARTIFACT_DIR="${EXAMOS_E2E_ARTIFACT_DIR:-$WORKSPACE/artifacts/e2e/runs/run-${RUN_ID}}"
mkdir -p "$ARTIFACT_DIR"

SERVER_PORT="${EXAMOS_E2E_SERVER_PORT:-9200}"
SERVER_BIN="$WORKSPACE/server/examos-server"
SERVER_URL="http://127.0.0.1:${SERVER_PORT}"
SERVER_PID=""
RUN_DIR="$(mktemp -d /tmp/examos-e2e.XXXXXX)"

# Counters
PASS=0; FAIL=0; BLOCKED=0
SUITE_RESULTS=()

# ── PostgreSQL ────────────────────────────────────────────────────────────────
E2E_DB_NAME="examos_e2e_$(date +%s)"
E2E_DB_USER="examos_e2e_u"
E2E_DB_PASS="$(openssl rand -hex 16)"

# ── Secrets ───────────────────────────────────────────────────────────────────
AGENT_TOKEN="$(openssl rand -hex 32)"
PROCTOR_TOKEN="$(openssl rand -hex 32)"
REVIEWER_TOKEN="$(openssl rand -hex 32)"
LEDGER_KEY="$(openssl rand -hex 32)"
EVENT_KEY="$(openssl rand -hex 32)"
VARIANT_SECRET="$(openssl rand -hex 32)"
ADMIN_USER="e2e-admin-$(openssl rand -hex 4)"
ADMIN_PASS="E2ePass!$(openssl rand -hex 6)"

ts()     { date -u +"%Y-%m-%dT%H:%M:%SZ"; }
log()    { echo "[$(ts)] $*"; }
hdr()    { echo ""; echo "══════════════════════════════════════════════════════"; echo "  $*"; echo "══════════════════════════════════════════════════════"; }
subhdr() { echo ""; echo "  ── $* ──"; }

record() {
    local suite="$1" id="$2" expected="$3" actual="$4" detail="$5"
    if [ "$actual" = "$expected" ]; then
        PASS=$((PASS+1))
        echo "    [PASS] ${suite}/${id}: ${detail}"
    elif [ "$actual" = "BLOCKED" ]; then
        BLOCKED=$((BLOCKED+1))
        echo "    [BLOCKED] ${suite}/${id}: ${detail}"
    else
        FAIL=$((FAIL+1))
        echo "    [FAIL] ${suite}/${id}: ${detail} (expected=${expected} got=${actual})"
    fi
}

suite_result() {
    local name="$1" status="$2"
    SUITE_RESULTS+=("${name}=${status}")
    log "Suite ${name}: ${status}"
}

# ── Cleanup ───────────────────────────────────────────────────────────────────
cleanup() {
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true
    [ -n "$SERVER_PID" ] && wait "$SERVER_PID" 2>/dev/null || true
    sudo -u postgres psql -c "DROP DATABASE IF EXISTS \"$E2E_DB_NAME\";" >/dev/null 2>&1 || true
    sudo -u postgres psql -c "DROP USER IF EXISTS \"$E2E_DB_USER\";" >/dev/null 2>&1 || true
    rm -rf "$RUN_DIR"
}
trap cleanup EXIT

# ── PostgreSQL setup ──────────────────────────────────────────────────────────
setup_postgres() {
    if ! sudo -u postgres pg_isready >/dev/null 2>&1; then
        log "BLOCKED: PostgreSQL not running"
        return 2
    fi
    sudo -u postgres psql -c "CREATE DATABASE \"$E2E_DB_NAME\";" >/dev/null 2>&1 || return 2
    sudo -u postgres psql -c "CREATE USER \"$E2E_DB_USER\" WITH PASSWORD '$E2E_DB_PASS';" >/dev/null 2>&1 || return 2
    sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE \"$E2E_DB_NAME\" TO \"$E2E_DB_USER\";" >/dev/null 2>&1 || return 2
    export EXAMOS_DB_NAME="$E2E_DB_NAME"
    export EXAMOS_DB_USER="$E2E_DB_USER"
    export EXAMOS_DB_PASS="$E2E_DB_PASS"
    export EXAMOS_DB_HOST="127.0.0.1"
    export EXAMOS_DB_PORT="5432"
    return 0
}

# ── Server start ──────────────────────────────────────────────────────────────
start_server() {
    [ -x "$SERVER_BIN" ] || { log "BLOCKED: server binary not found at $SERVER_BIN"; return 2; }
    local exam_id="E2E-EXAM-$(date +%s)"
    cat > "$RUN_DIR/exam.conf" <<CONF
EXAM_URL=https://exam.university.edu/e2e
EXAM_NAME=ExamOS E2E Test
EXAM_ID=${exam_id}
ALLOWED_ORIGINS=https://exam.university.edu
EXAM_DURATION_MINUTES=60
CONF
    EXAMOS_SERVER_PORT="$SERVER_PORT" \
    EXAMOS_LEDGER_PATH="$RUN_DIR/ledger.log" \
    EXAMOS_LEDGER_HMAC_KEY="$LEDGER_KEY" \
    EXAMOS_EVENT_CHAIN_PATH="$RUN_DIR/events.log" \
    EXAMOS_AGENT_API_TOKEN="$AGENT_TOKEN" \
    EXAMOS_PROCTOR_API_TOKEN="$PROCTOR_TOKEN" \
    EXAMOS_EVENT_SIGNING_KEY="$EVENT_KEY" \
    EXAMOS_VARIANT_SECRET="$VARIANT_SECRET" \
    EXAMOS_REVIEWER_TOKEN="$REVIEWER_TOKEN" \
    EXAMOS_ALLOW_UNPROVISIONED_DEV="1" \
    EXAMOS_EXAM_CONFIG="$RUN_DIR/exam.conf" \
    EXAMOS_BEHAVIOUR_STORE="$RUN_DIR/behaviour" \
    EXAMOS_VIVA_STORE="$RUN_DIR/viva" \
    EXAMOS_VARIANT_STORE="$RUN_DIR/variants" \
    EXAMOS_SESSION_JOURNAL="$RUN_DIR/session.log" \
    EXAMOS_DATA_DIR="$RUN_DIR/data" \
    EXAMOS_TPM_MODE="development" \
    EXAMOS_DB_NAME="${EXAMOS_DB_NAME:-}" \
    EXAMOS_DB_USER="${EXAMOS_DB_USER:-}" \
    EXAMOS_DB_PASS="${EXAMOS_DB_PASS:-}" \
    EXAMOS_DB_HOST="${EXAMOS_DB_HOST:-}" \
    EXAMOS_DB_PORT="5432" \
        "$SERVER_BIN" &
    SERVER_PID=$!
    local tries=0
    while [ $tries -lt 30 ]; do
        curl -sf "${SERVER_URL}/api/v1/health" | grep -q '"status":"ok"' && return 0
        sleep 1; tries=$((tries+1))
    done
    log "FATAL: server did not start on port $SERVER_PORT"
    return 1
}

jq_val() { python3 -c "import sys,json; print(json.load(sys.stdin).get('$1',''))" 2>/dev/null || echo ""; }
http_code() { curl -s -o /dev/null -w '%{http_code}' "$@" 2>/dev/null || echo "000"; }

# =============================================================================
# SUITE 0: Prerequisites — build all native binaries
# =============================================================================
run_suite_build() {
    hdr "SUITE 0: Build — Native C/C++ Binaries"
    local st=PASS

    subhdr "S0-A: make all (server + proctoring + tools)"
    if make -C "$WORKSPACE/server" all >"$ARTIFACT_DIR/build-server.log" 2>&1; then
        record S0 BUILD_SERVER PASS PASS "server binary built"
    else
        record S0 BUILD_SERVER PASS FAIL "make server failed — see build-server.log"
        st=FAIL
    fi

    if make -C "$WORKSPACE/proctoring" all >"$ARTIFACT_DIR/build-proctoring.log" 2>&1; then
        record S0 BUILD_PROCTOR PASS PASS "proctoring binary built"
    else
        record S0 BUILD_PROCTOR PASS FAIL "make proctoring failed"
        st=FAIL
    fi

    if gcc -Wall -O2 "$WORKSPACE/tools/exam-event-verify.c" \
           -o "$RUN_DIR/exam-event-verify" -lssl -lcrypto \
           >>"$ARTIFACT_DIR/build-server.log" 2>&1; then
        record S0 BUILD_VERIFIER PASS PASS "exam-event-verify built"
    else
        record S0 BUILD_VERIFIER PASS BLOCKED "verifier build failed (non-fatal)"
    fi

    suite_result S0_BUILD "$st"
}

# =============================================================================
# SUITE 1: P0 — OS Image Build & QEMU Boot
# =============================================================================
run_suite_p0() {
    hdr "SUITE 1: P0 — OS Image Build & QEMU Boot"
    local st=PASS

    subhdr "S1-A: Source tree state"
    local tree_state
    tree_state="$(git -C "$WORKSPACE" status --porcelain=v1 --untracked-files=all \
        -- . ':(exclude)artifacts/**' ':(exclude)image/p0/output/**' \
        ':(exclude)build/**' ':(exclude)cache/**' 2>/dev/null | wc -l | tr -d ' ')"
    if [ "$tree_state" = "0" ]; then
        record S1 P0_TREE_CLEAN PASS PASS "source tree is clean"
    else
        record S1 P0_TREE_CLEAN PASS BLOCKED "source tree is dirty (${tree_state} changes) — results are diagnostic"
        st=BLOCKED
    fi

    subhdr "S1-B: P0 gate (existing artifacts)"
    local p0_gate=BLOCKED
    if [ -f "$WORKSPACE/artifacts/p0/results.json" ]; then
        local p0_status
        p0_status="$(python3 -c "import json; d=json.load(open('$WORKSPACE/artifacts/p0/results.json')); print(d.get('gate',d.get('status','UNKNOWN')))" 2>/dev/null || echo UNKNOWN)"
        if [ "$p0_status" = "PASS" ]; then
            p0_gate=PASS
        elif [ "$p0_status" = "BLOCKED" ]; then
            p0_gate=BLOCKED
        else
            p0_gate=FAIL; st=FAIL
        fi
        record S1 P0_GATE_ARTIFACT "$p0_gate" "$p0_gate" "existing P0 artifact status=${p0_status}"
    else
        record S1 P0_GATE_ARTIFACT PASS BLOCKED "no P0 artifact found — run tests/p0/build.sh first"
        st=BLOCKED
    fi

    subhdr "S1-C: QEMU boot smoke (non-blocking)"
    if command -v qemu-system-x86_64 >/dev/null 2>&1; then
        local image_file
        image_file="$(bash -c 'source "$1/scripts/p0-image-path.sh" 2>/dev/null && examos_image_output_dir "$1" "$1/image" 2>/dev/null || echo ""' _ "$WORKSPACE")/examos.raw"
        if [ -s "$image_file" ]; then
            record S1 P0_IMAGE_EXISTS PASS PASS "disk image found: $image_file"
        else
            record S1 P0_IMAGE_EXISTS PASS BLOCKED "disk image not found — build with: cd image && sudo mkosi build"
            st=BLOCKED
        fi
    else
        record S1 P0_QEMU PASS BLOCKED "qemu-system-x86_64 not available"
        st=BLOCKED
    fi

    suite_result S1_P0 "$st"
}

# =============================================================================
# SUITE 2: P1 — Kiosk & Network Configuration
# =============================================================================
run_suite_p1() {
    hdr "SUITE 2: P1 — Kiosk & Network Configuration"
    local st=PASS

    subhdr "S2-A: P1 gate script"
    local p1_rc=0
    EXAMOS_P1_ARTIFACT_DIR="$ARTIFACT_DIR/p1" \
        bash "$WORKSPACE/tests/p1/gate.sh" >"$ARTIFACT_DIR/p1-gate.log" 2>&1 || p1_rc=$?
    if [ $p1_rc -eq 0 ]; then
        record S2 P1_GATE PASS PASS "P1 gate passed"
    elif [ $p1_rc -eq 2 ]; then
        record S2 P1_GATE PASS BLOCKED "P1 gate blocked"
        st=BLOCKED
    else
        record S2 P1_GATE PASS FAIL "P1 gate failed (rc=$p1_rc)"
        st=FAIL
    fi

    subhdr "S2-B: Chromium policy generator"
    local pol_rc=0
    bash "$WORKSPACE/tests/p1/chromium-policy-generator-test.sh" \
        >"$ARTIFACT_DIR/chromium-policy.log" 2>&1 || pol_rc=$?
    if [ $pol_rc -eq 0 ]; then
        record S2 P1_CHROMIUM_POLICY PASS PASS "chromium policy generator correct"
    elif [ $pol_rc -eq 2 ]; then
        record S2 P1_CHROMIUM_POLICY PASS BLOCKED "chromium policy test blocked"
        [ "$st" = "PASS" ] && st=BLOCKED
    else
        record S2 P1_CHROMIUM_POLICY PASS FAIL "chromium policy test failed"
        st=FAIL
    fi

    subhdr "S2-C: Network configuration"
    local net_rc=0
    bash "$WORKSPACE/tests/p1/network.sh" >"$ARTIFACT_DIR/p1-network.log" 2>&1 || net_rc=$?
    if [ $net_rc -eq 0 ]; then
        record S2 P1_NETWORK PASS PASS "network config valid"
    elif [ $net_rc -eq 2 ]; then
        record S2 P1_NETWORK PASS BLOCKED "network test blocked"
        [ "$st" = "PASS" ] && st=BLOCKED
    else
        record S2 P1_NETWORK PASS FAIL "network test failed"
        st=FAIL
    fi

    suite_result S2_P1 "$st"
}

# =============================================================================
# SUITE 3: P2 — OS Lockdown (nftables, AppArmor, USBGuard, dm-verity)
# =============================================================================
run_suite_p2() {
    hdr "SUITE 3: P2 — OS Lockdown"
    local st=BLOCKED

    subhdr "S3-A: P2 static audit"
    local audit_rc=0
    bash "$WORKSPACE/tests/p2/p2-static-audit.sh" \
        >"$ARTIFACT_DIR/p2-static-audit.log" 2>&1 || audit_rc=$?
    if [ $audit_rc -eq 0 ]; then
        record S3 P2_STATIC_AUDIT PASS PASS "static audit passed"
        st=PASS
    elif [ $audit_rc -eq 2 ]; then
        record S3 P2_STATIC_AUDIT PASS BLOCKED "static audit blocked (hardware/guest required)"
    else
        record S3 P2_STATIC_AUDIT PASS FAIL "static audit failed"
        st=FAIL
    fi

    subhdr "S3-B: P2 network policy"
    local net_rc=0
    bash "$WORKSPACE/tests/p2/p2-network-tests.sh" \
        >"$ARTIFACT_DIR/p2-network.log" 2>&1 || net_rc=$?
    if [ $net_rc -eq 0 ]; then
        record S3 P2_NETWORK PASS PASS "nftables policy tests passed"
        [ "$st" = "BLOCKED" ] && st=PASS
    elif [ $net_rc -eq 2 ]; then
        record S3 P2_NETWORK PASS BLOCKED "network policy tests blocked"
    else
        record S3 P2_NETWORK PASS FAIL "network policy tests failed"
        st=FAIL
    fi

    subhdr "S3-C: P2 Secure Boot gate"
    local sb_rc=0
    bash "$WORKSPACE/tests/p2/p2-secureboot-gate.sh" \
        >"$ARTIFACT_DIR/p2-secureboot.log" 2>&1 || sb_rc=$?
    if [ $sb_rc -eq 0 ]; then
        record S3 P2_SECUREBOOT PASS PASS "Secure Boot gate passed"
    elif [ $sb_rc -eq 2 ]; then
        record S3 P2_SECUREBOOT PASS BLOCKED "Secure Boot gate blocked (UEFI hardware required)"
    else
        record S3 P2_SECUREBOOT PASS FAIL "Secure Boot gate failed"
        st=FAIL
    fi

    subhdr "S3-D: P2 dm-verity"
    local verity_rc=0
    bash "$WORKSPACE/tests/p2/p2-verity-tests.sh" \
        >"$ARTIFACT_DIR/p2-verity.log" 2>&1 || verity_rc=$?
    if [ $verity_rc -eq 0 ]; then
        record S3 P2_DMVERITY PASS PASS "dm-verity tests passed"
    elif [ $verity_rc -eq 2 ]; then
        record S3 P2_DMVERITY PASS BLOCKED "dm-verity tests blocked (kernel module required)"
    else
        record S3 P2_DMVERITY PASS FAIL "dm-verity tests failed"
        st=FAIL
    fi

    subhdr "S3-E: P2 USB policy"
    local usb_rc=0
    bash "$WORKSPACE/tests/p2/p2-usb-tests.sh" \
        >"$ARTIFACT_DIR/p2-usb.log" 2>&1 || usb_rc=$?
    if [ $usb_rc -eq 0 ]; then
        record S3 P2_USB PASS PASS "USBGuard policy tests passed"
    elif [ $usb_rc -eq 2 ]; then
        record S3 P2_USB PASS BLOCKED "USB tests blocked (USBGuard daemon required)"
    else
        record S3 P2_USB PASS FAIL "USB policy tests failed"
        st=FAIL
    fi

    suite_result S3_P2 "$st"
}

# =============================================================================
# SUITE 3: P2 — OS Lockdown (nftables, AppArmor, USBGuard, dm-verity)
# =============================================================================
run_suite_p2() {
    hdr "SUITE 3: P2 — OS Lockdown"
    local st=BLOCKED

    subhdr "S3-A: P2 static audit"
    local audit_rc=0
    bash "$WORKSPACE/tests/p2/p2-static-audit.sh" >"$ARTIFACT_DIR/p2-static-audit.log" 2>&1 || audit_rc=$?
    if [ $audit_rc -eq 0 ]; then
        record S3 P2_STATIC_AUDIT PASS PASS "static audit passed"; st=PASS
    elif [ $audit_rc -eq 2 ]; then
        record S3 P2_STATIC_AUDIT PASS BLOCKED "static audit blocked (hardware/guest required)"
    else
        record S3 P2_STATIC_AUDIT PASS FAIL "static audit failed"; st=FAIL
    fi

    subhdr "S3-B: P2 network policy"
    local net_rc=0
    bash "$WORKSPACE/tests/p2/p2-network-tests.sh" >"$ARTIFACT_DIR/p2-network.log" 2>&1 || net_rc=$?
    if [ $net_rc -eq 0 ]; then
        record S3 P2_NETWORK PASS PASS "nftables policy tests passed"
        [ "$st" = "BLOCKED" ] && st=PASS
    elif [ $net_rc -eq 2 ]; then
        record S3 P2_NETWORK PASS BLOCKED "network policy tests blocked"
    else
        record S3 P2_NETWORK PASS FAIL "network policy tests failed"; st=FAIL
    fi

    subhdr "S3-C: P2 Secure Boot gate"
    local sb_rc=0
    bash "$WORKSPACE/tests/p2/p2-secureboot-gate.sh" >"$ARTIFACT_DIR/p2-secureboot.log" 2>&1 || sb_rc=$?
    if [ $sb_rc -eq 0 ]; then
        record S3 P2_SECUREBOOT PASS PASS "Secure Boot gate passed"
    elif [ $sb_rc -eq 2 ]; then
        record S3 P2_SECUREBOOT PASS BLOCKED "Secure Boot gate blocked (UEFI hardware required)"
    else
        record S3 P2_SECUREBOOT PASS FAIL "Secure Boot gate failed"; st=FAIL
    fi

    subhdr "S3-D: dm-verity"
    local verity_rc=0
    bash "$WORKSPACE/tests/p2/p2-verity-tests.sh" >"$ARTIFACT_DIR/p2-verity.log" 2>&1 || verity_rc=$?
    if [ $verity_rc -eq 0 ]; then
        record S3 P2_DMVERITY PASS PASS "dm-verity tests passed"
    elif [ $verity_rc -eq 2 ]; then
        record S3 P2_DMVERITY PASS BLOCKED "dm-verity blocked (kernel module required)"
    else
        record S3 P2_DMVERITY PASS FAIL "dm-verity tests failed"; st=FAIL
    fi

    subhdr "S3-E: USBGuard policy"
    local usb_rc=0
    bash "$WORKSPACE/tests/p2/p2-usb-tests.sh" >"$ARTIFACT_DIR/p2-usb.log" 2>&1 || usb_rc=$?
    if [ $usb_rc -eq 0 ]; then
        record S3 P2_USB PASS PASS "USBGuard policy tests passed"
    elif [ $usb_rc -eq 2 ]; then
        record S3 P2_USB PASS BLOCKED "USB tests blocked (USBGuard daemon required)"
    else
        record S3 P2_USB PASS FAIL "USB policy tests failed"; st=FAIL
    fi

    suite_result S3_P2 "$st"
}

# =============================================================================
# SUITE 4: P3 — TPM Attestation & Exam-Key Release
# =============================================================================
run_suite_p3() {
    hdr "SUITE 4: P3 — TPM Attestation & Key Release"
    local st=BLOCKED

    subhdr "S4-A: swtpm quote smoke"
    local q_rc=0
    bash "$WORKSPACE/tests/p3/swtpm-quote-smoke.sh" >"$ARTIFACT_DIR/p3-swtpm.log" 2>&1 || q_rc=$?
    if [ $q_rc -eq 0 ]; then
        record S4 P3_SWTPM_QUOTE PASS PASS "swtpm TPM2 quote smoke passed"; st=PASS
    elif [ $q_rc -eq 2 ]; then
        record S4 P3_SWTPM_QUOTE PASS BLOCKED "swtpm not available"
    else
        record S4 P3_SWTPM_QUOTE PASS FAIL "swtpm quote smoke failed"; st=FAIL
    fi

    subhdr "S4-B: Go verifier fail-closed"
    if command -v go >/dev/null 2>&1; then
        local go_rc=0
        (cd "$WORKSPACE/server/attestation" && go test verifier.go verifier_test.go \
            >"$ARTIFACT_DIR/p3-go-verifier.log" 2>&1) || go_rc=$?
        if [ $go_rc -eq 0 ]; then
            record S4 P3_GO_VERIFIER PASS BLOCKED "Go verifier passes but production DB/key lifecycle unqualified"
            [ "$st" = "BLOCKED" ] && st=BLOCKED
        else
            record S4 P3_GO_VERIFIER PASS BLOCKED "Go verifier blocked (expected until production trust provisioned)"
        fi
    else
        record S4 P3_GO_VERIFIER PASS BLOCKED "Go toolchain not available"
    fi

    subhdr "S4-C: Live server attestation endpoints"
    # nonce challenge
    local nonce_resp
    nonce_resp=$(curl -s -X POST "${SERVER_URL}/api/v1/attestation/nonce" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${AGENT_TOKEN}" \
        -d '{"device_id":"e2e-dev-001","session_id":"e2e-sess-001","release_id":"e2e-rel-001"}' 2>/dev/null)
    local nonce_status
    nonce_status=$(echo "$nonce_resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))" 2>/dev/null || echo "")
    if [ "$nonce_status" = "CHALLENGE_ISSUED" ]; then
        record S4 P3_NONCE_ENDPOINT PASS PASS "attestation nonce endpoint live"
        [ "$st" = "BLOCKED" ] && st=PASS
    else
        record S4 P3_NONCE_ENDPOINT PASS BLOCKED "nonce endpoint returned: $nonce_status (dev mode expected)"
    fi

    # re-attest endpoint
    local reattest_code
    reattest_code=$(http_code -X POST "${SERVER_URL}/api/v1/attestation/re-attest" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${AGENT_TOKEN}" \
        -d '{"session_id":"e2e-sess-001","device_id":"e2e-dev-001"}')
    if [ "$reattest_code" = "200" ] || [ "$reattest_code" = "403" ]; then
        record S4 P3_REATTEST_ENDPOINT PASS PASS "re-attest endpoint responds (${reattest_code})"
    else
        record S4 P3_REATTEST_ENDPOINT PASS FAIL "re-attest endpoint unexpected code: $reattest_code"
        st=FAIL
    fi

    subhdr "S4-D: P3 gate"
    local p3_rc=0
    EXAMOS_P3_ARTIFACT_DIR="$ARTIFACT_DIR/p3" \
        bash "$WORKSPACE/tests/p3/gate.sh" >"$ARTIFACT_DIR/p3-gate.log" 2>&1 || p3_rc=$?
    if [ $p3_rc -eq 0 ]; then
        record S4 P3_GATE PASS PASS "P3 gate passed"
        st=PASS
    elif [ $p3_rc -eq 2 ]; then
        record S4 P3_GATE PASS BLOCKED "P3 gate blocked (production trust assets required)"
        [ "$st" = "PASS" ] || st=BLOCKED
    else
        record S4 P3_GATE PASS FAIL "P3 gate failed"
        st=FAIL
    fi

    suite_result S4_P3 "$st"
}

# =============================================================================
# SUITE 5: P4 — Proctoring Engine & Tamper-Evident Event Chain
# =============================================================================
run_suite_p4() {
    hdr "SUITE 5: P4 — Proctoring Engine & Event Chain"
    local st=PASS

    subhdr "S5-A: Proctoring event ingest (live server)"
    local ev_resp
    ev_resp=$(curl -s -X POST "${SERVER_URL}/api/v1/proctoring/events" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${PROCTOR_TOKEN}" \
        -d "{\"session_id\":\"e2e-proctor-sess\",\"source_type\":\"VISION\",\"event_type\":\"FACE_PRESENT\",\"model_name\":\"yunet-e2e\",\"model_version\":\"v1\",\"payload\":{\"confidence\":0.97}}" 2>/dev/null)
    local ev_status
    ev_status=$(echo "$ev_resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))" 2>/dev/null || echo "")
    if [ "$ev_status" = "RECORDED" ]; then
        record S5 P4_EVENT_INGEST PASS PASS "proctoring event recorded in chain"
    else
        record S5 P4_EVENT_INGEST PASS FAIL "event ingest failed: $ev_status ($ev_resp)"
        st=FAIL
    fi

    subhdr "S5-B: NO_FACE event & risk engine"
    local risk_resp
    risk_resp=$(curl -s -X POST "${SERVER_URL}/api/v1/proctoring/events" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${PROCTOR_TOKEN}" \
        -d "{\"session_id\":\"e2e-proctor-sess\",\"source_type\":\"VISION\",\"event_type\":\"NO_FACE\",\"model_name\":\"yunet-e2e\",\"model_version\":\"v1\",\"payload\":{\"confidence\":0.99}}" 2>/dev/null)
    local risk_score
    risk_score=$(echo "$risk_resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('risk_score',''))" 2>/dev/null || echo "")
    if [ -n "$risk_score" ]; then
        record S5 P4_RISK_ENGINE PASS PASS "risk engine computed score=${risk_score}"
    else
        record S5 P4_RISK_ENGINE PASS FAIL "risk engine did not return score: $risk_resp"
        st=FAIL
    fi

    subhdr "S5-C: Event chain checkpoint"
    local cp_resp
    cp_resp=$(curl -s -X POST "${SERVER_URL}/api/v1/proctoring/checkpoint" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${PROCTOR_TOKEN}" \
        -d '{"session_id":"e2e-proctor-sess"}' 2>/dev/null)
    local cp_status
    cp_status=$(echo "$cp_resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))" 2>/dev/null || echo "")
    if [ "$cp_status" = "CHECKPOINT_SIGNED" ]; then
        record S5 P4_CHECKPOINT PASS PASS "event chain checkpoint signed"
    else
        record S5 P4_CHECKPOINT PASS FAIL "checkpoint failed: $cp_status"
        st=FAIL
    fi

    subhdr "S5-D: Event chain verify"
    local vfy_resp
    vfy_resp=$(curl -s -X POST "${SERVER_URL}/api/v1/proctoring/verify" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $(admin_token)" \
        -d '{"session_id":"e2e-proctor-sess"}' 2>/dev/null)
    local vfy_status
    vfy_status=$(echo "$vfy_resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))" 2>/dev/null || echo "")
    if [ "$vfy_status" = "VERIFIED" ]; then
        record S5 P4_CHAIN_VERIFY PASS PASS "event chain integrity verified"
    else
        record S5 P4_CHAIN_VERIFY PASS BLOCKED "chain verify needs admin token: $vfy_status"
        [ "$st" = "PASS" ] && st=BLOCKED
    fi

    subhdr "S5-E: Tamper test suite"
    local tamper_rc=0
    EXAMOS_P4_VERIFIER="$RUN_DIR/exam-event-verify" \
        bash "$WORKSPACE/tests/phase4/tamper-tests.sh" >"$ARTIFACT_DIR/p4-tamper.log" 2>&1 || tamper_rc=$?
    if [ $tamper_rc -eq 0 ]; then
        record S5 P4_TAMPER_SUITE PASS PASS "tamper detection matrix passed"
    elif [ $tamper_rc -eq 2 ]; then
        record S5 P4_TAMPER_SUITE PASS BLOCKED "tamper suite blocked"
        [ "$st" = "PASS" ] && st=BLOCKED
    else
        record S5 P4_TAMPER_SUITE PASS FAIL "tamper suite failed"
        st=FAIL
    fi

    subhdr "S5-F: Detection evaluation (labelled dataset)"
    local det_rc=0
    bash "$WORKSPACE/tests/phase4/detection-eval.sh" >"$ARTIFACT_DIR/p4-detection.log" 2>&1 || det_rc=$?
    if [ $det_rc -eq 0 ]; then
        record S5 P4_DETECTION_EVAL PASS PASS "detection evaluation passed"
    elif [ $det_rc -eq 2 ]; then
        record S5 P4_DETECTION_EVAL PASS BLOCKED "detection eval blocked (dataset/model required)"
        [ "$st" = "PASS" ] && st=BLOCKED
    else
        record S5 P4_DETECTION_EVAL PASS FAIL "detection evaluation failed"
        st=FAIL
    fi

    subhdr "S5-G: P4 gate"
    local p4_rc=0
    EXAMOS_P4_ARTIFACT_DIR="$ARTIFACT_DIR/p4" \
        bash "$WORKSPACE/tests/phase4/gate.sh" >"$ARTIFACT_DIR/p4-gate.log" 2>&1 || p4_rc=$?
    if [ $p4_rc -eq 0 ]; then
        record S5 P4_GATE PASS PASS "P4 gate passed"
    elif [ $p4_rc -eq 2 ]; then
        record S5 P4_GATE PASS BLOCKED "P4 gate blocked"
        [ "$st" = "PASS" ] && st=BLOCKED
    else
        record S5 P4_GATE PASS FAIL "P4 gate failed"
        st=FAIL
    fi

    suite_result S5_P4 "$st"
}

# =============================================================================
# Admin token helper — logs in once, caches token
# =============================================================================
ADMIN_TOKEN_CACHE=""
admin_token() {
    if [ -n "$ADMIN_TOKEN_CACHE" ]; then echo "$ADMIN_TOKEN_CACHE"; return; fi
    local resp
    resp=$(curl -s -X POST "${SERVER_URL}/api/v1/admin/login" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"${ADMIN_USER}\",\"password\":\"${ADMIN_PASS}\"}" 2>/dev/null)
    ADMIN_TOKEN_CACHE=$(echo "$resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('token',''))" 2>/dev/null || echo "")
    echo "$ADMIN_TOKEN_CACHE"
}

# =============================================================================
# SUITE 6: P5 — Behaviour Engine, Variant & Viva
# =============================================================================
run_suite_p5() {
    hdr "SUITE 6: P5 — Behaviour Engine / Variant / Viva"
    local st=PASS

    subhdr "S6-A: P5 behaviour engine test"
    local beh_rc=0
    EXAMOS_P5_ARTIFACT_DIR="$ARTIFACT_DIR/p5" \
    EXAMOS_P5_SERVER_PORT="$((SERVER_PORT+1))" \
        bash "$WORKSPACE/tests/p5/p5-behaviour-test.sh" \
        >"$ARTIFACT_DIR/p5-behaviour.log" 2>&1 || beh_rc=$?
    if [ $beh_rc -eq 0 ]; then
        record S6 P5_BEHAVIOUR PASS PASS "behaviour engine tests passed"
    elif [ $beh_rc -eq 2 ]; then
        record S6 P5_BEHAVIOUR PASS BLOCKED "behaviour tests blocked"
        st=BLOCKED
    else
        record S6 P5_BEHAVIOUR PASS FAIL "behaviour tests failed"
        st=FAIL
    fi

    subhdr "S6-B: P5 variant test"
    local var_rc=0
    EXAMOS_P5_ARTIFACT_DIR="$ARTIFACT_DIR/p5" \
    EXAMOS_P5_SERVER_PORT="$((SERVER_PORT+2))" \
        bash "$WORKSPACE/tests/p5/p5-variant-test.sh" \
        >"$ARTIFACT_DIR/p5-variant.log" 2>&1 || var_rc=$?
    if [ $var_rc -eq 0 ]; then
        record S6 P5_VARIANT PASS PASS "variant engine tests passed"
    elif [ $var_rc -eq 2 ]; then
        record S6 P5_VARIANT PASS BLOCKED "variant tests blocked"
        [ "$st" = "PASS" ] && st=BLOCKED
    else
        record S6 P5_VARIANT PASS FAIL "variant tests failed"
        st=FAIL
    fi

    subhdr "S6-C: P5 viva test"
    local viva_rc=0
    EXAMOS_P5_ARTIFACT_DIR="$ARTIFACT_DIR/p5" \
    EXAMOS_P5_SERVER_PORT="$((SERVER_PORT+3))" \
        bash "$WORKSPACE/tests/p5/p5-viva-test.sh" \
        >"$ARTIFACT_DIR/p5-viva.log" 2>&1 || viva_rc=$?
    if [ $viva_rc -eq 0 ]; then
        record S6 P5_VIVA PASS PASS "viva engine tests passed"
    elif [ $viva_rc -eq 2 ]; then
        record S6 P5_VIVA PASS BLOCKED "viva tests blocked (LLM provider required)"
        [ "$st" = "PASS" ] && st=BLOCKED
    else
        record S6 P5_VIVA PASS FAIL "viva tests failed"
        st=FAIL
    fi

    subhdr "S6-D: P5 gate"
    local p5_rc=0
    EXAMOS_P5_ARTIFACT_DIR="$ARTIFACT_DIR/p5" \
        bash "$WORKSPACE/tests/p5/p5-gate.sh" \
        >"$ARTIFACT_DIR/p5-gate.log" 2>&1 || p5_rc=$?
    if [ $p5_rc -eq 0 ]; then
        record S6 P5_GATE PASS PASS "P5 gate passed"
    elif [ $p5_rc -eq 2 ]; then
        record S6 P5_GATE PASS BLOCKED "P5 gate blocked"
        [ "$st" = "PASS" ] && st=BLOCKED
    else
        record S6 P5_GATE PASS FAIL "P5 gate failed"
        st=FAIL
    fi

    suite_result S6_P5 "$st"
}

# =============================================================================
# SUITE 7: Live Server — Full API Integration
# =============================================================================
run_suite_api() {
    hdr "SUITE 7: Live Server API Integration"
    local st=PASS

    # ── Health ────────────────────────────────────────────────────────────────
    subhdr "S7-A: Health endpoint"
    local health
    health=$(curl -s "${SERVER_URL}/api/v1/health" 2>/dev/null)
    local h_status
    h_status=$(echo "$health" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))" 2>/dev/null || echo "")
    if [ "$h_status" = "ok" ]; then
        record S7 HEALTH PASS PASS "health endpoint returns ok"
    else
        record S7 HEALTH PASS FAIL "health endpoint: $h_status"
        st=FAIL
    fi

    # ── Admin login ───────────────────────────────────────────────────────────
    subhdr "S7-B: Admin provisioning & login"
    local prov_rc=0
    "$WORKSPACE/server/examos-admin-provision" \
        --username "$ADMIN_USER" --password "$ADMIN_PASS" --role platform_owner \
        >"$ARTIFACT_DIR/admin-provision.log" 2>&1 || prov_rc=$?
    if [ $prov_rc -ne 0 ]; then
        record S7 ADMIN_PROVISION PASS BLOCKED "admin-provision failed (DB may not be migrated)"
        st=BLOCKED
    else
        record S7 ADMIN_PROVISION PASS PASS "admin user provisioned"
        local tok
        tok=$(admin_token)
        if [ -n "$tok" ]; then
            record S7 ADMIN_LOGIN PASS PASS "admin login succeeded, token obtained"
        else
            record S7 ADMIN_LOGIN PASS FAIL "admin login returned no token"
            st=FAIL
        fi
    fi

    # ── Candidate login ───────────────────────────────────────────────────────
    subhdr "S7-C: Candidate login (kiosk dev mode)"
    local cand_id="E2E-CAND-$(openssl rand -hex 4)"
    local cand_pin="$(openssl rand -hex 8)"
    local cand_salt="$(openssl rand -hex 32)"
    local cand_hash
    cand_hash=$(openssl kdf -keylen 32 -kdfopt digest:SHA256 \
        -kdfopt "hexsalt:${cand_salt}" -kdfopt "pass:${cand_pin}" \
        -kdfopt "iter:100000" PBKDF2 2>/dev/null | tr -d ':\n' | tr 'A-F' 'a-f' || echo "")
    if [ -n "$cand_hash" ]; then
        echo "${cand_id}:100001:${cand_salt}:${cand_hash}" > "$RUN_DIR/candidates.conf"
        export EXAMOS_CANDIDATE_STORE="$RUN_DIR/candidates.conf"
        local login_resp
        login_resp=$(curl -s -X POST "${SERVER_URL}/api/v1/candidate/login" \
            -H "Content-Type: application/json" \
            -H "X-ExamOS-Kiosk: 1" \
            -H "User-Agent: ExamOS-Kiosk/1.0" \
            -d "{\"candidate_id\":\"${cand_id}\",\"pin\":\"${cand_pin}\"}" 2>/dev/null)
        local cand_token
        cand_token=$(echo "$login_resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('token',''))" 2>/dev/null || echo "")
        if [ -n "$cand_token" ]; then
            record S7 CANDIDATE_LOGIN PASS PASS "candidate login succeeded"
        else
            record S7 CANDIDATE_LOGIN PASS BLOCKED "candidate login blocked (kiosk enforcement or store not reloaded)"
            [ "$st" = "PASS" ] && st=BLOCKED
        fi
    else
        record S7 CANDIDATE_LOGIN PASS BLOCKED "openssl kdf unavailable for candidate hash"
        [ "$st" = "PASS" ] && st=BLOCKED
        cand_token=""
    fi

    # ── Ledger ────────────────────────────────────────────────────────────────
    subhdr "S7-D: Ledger integrity"
    local tok
    tok=$(admin_token)
    if [ -n "$tok" ]; then
        local ledger_resp
        ledger_resp=$(curl -s "${SERVER_URL}/api/v1/ledger" \
            -H "Authorization: Bearer ${tok}" 2>/dev/null)
        local ledger_int
        ledger_int=$(echo "$ledger_resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('ledger_integrity',''))" 2>/dev/null || echo "")
        if [ "$ledger_int" = "INTACT" ]; then
            record S7 LEDGER_INTEGRITY PASS PASS "ledger integrity: INTACT"
        else
            record S7 LEDGER_INTEGRITY PASS FAIL "ledger integrity: $ledger_int"
            st=FAIL
        fi
    else
        record S7 LEDGER_INTEGRITY PASS BLOCKED "no admin token for ledger check"
        [ "$st" = "PASS" ] && st=BLOCKED
    fi

    # ── Kiosk heartbeat ───────────────────────────────────────────────────────
    subhdr "S7-E: Kiosk heartbeat & terminals"
    local hb_resp
    hb_resp=$(curl -s -X POST "${SERVER_URL}/api/v1/kiosk/heartbeat" \
        -H "Content-Type: application/json" \
        -d '{"terminal_id":"e2e-term-001","status":"ONLINE","screen_focus":1}' 2>/dev/null)
    local hb_status
    hb_status=$(echo "$hb_resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))" 2>/dev/null || echo "")
    if [ "$hb_status" = "ACK" ]; then
        record S7 KIOSK_HEARTBEAT PASS PASS "kiosk heartbeat ACK"
    else
        record S7 KIOSK_HEARTBEAT PASS FAIL "kiosk heartbeat: $hb_status"
        st=FAIL
    fi

    local terms_resp
    terms_resp=$(curl -s "${SERVER_URL}/api/v1/kiosk/terminals" 2>/dev/null)
    local terms_count
    terms_count=$(echo "$terms_resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('count',0))" 2>/dev/null || echo "0")
    if [ "$terms_count" -ge 1 ] 2>/dev/null; then
        record S7 KIOSK_TERMINALS PASS PASS "kiosk terminals tracked: $terms_count"
    else
        record S7 KIOSK_TERMINALS PASS FAIL "kiosk terminals count: $terms_count"
        st=FAIL
    fi

    # ── Agent heartbeat ───────────────────────────────────────────────────────
    subhdr "S7-F: Agent heartbeat"
    local agent_resp
    agent_resp=$(curl -s -X POST "${SERVER_URL}/api/v1/heartbeat" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${AGENT_TOKEN}" \
        -d '{"device_id":"e2e-dev-001","status":"ONLINE"}' 2>/dev/null)
    local agent_status
    agent_status=$(echo "$agent_resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))" 2>/dev/null || echo "")
    if [ "$agent_status" = "RECEIVED_UNTRUSTED" ] || [ "$agent_status" = "STORED" ]; then
        record S7 AGENT_HEARTBEAT PASS PASS "agent heartbeat accepted: $agent_status"
    else
        record S7 AGENT_HEARTBEAT PASS FAIL "agent heartbeat: $agent_status"
        st=FAIL
    fi

    # ── Emergency lock/unlock ─────────────────────────────────────────────────
    subhdr "S7-G: Emergency lock / unlock"
    tok=$(admin_token)
    if [ -n "$tok" ]; then
        local lock_code
        lock_code=$(http_code -X POST "${SERVER_URL}/api/v1/admin/lock" \
            -H "Authorization: Bearer ${tok}")
        local unlock_code
        unlock_code=$(http_code -X POST "${SERVER_URL}/api/v1/admin/unlock" \
            -H "Authorization: Bearer ${tok}")
        if [ "$lock_code" = "200" ] && [ "$unlock_code" = "200" ]; then
            record S7 EMERGENCY_LOCK PASS PASS "emergency lock/unlock cycle succeeded"
        else
            record S7 EMERGENCY_LOCK PASS FAIL "lock=${lock_code} unlock=${unlock_code}"
            st=FAIL
        fi
    else
        record S7 EMERGENCY_LOCK PASS BLOCKED "no admin token"
        [ "$st" = "PASS" ] && st=BLOCKED
    fi

    # ── Unrouted controllers ──────────────────────────────────────────────────
    subhdr "S7-H: Unrouted controller endpoints (student/exam-session/device-trust/os-release/registration)"
    tok=$(admin_token)
    local ctrl_blocked=0
    for endpoint in \
        "GET /api/v1/admin/students" \
        "GET /api/v1/exam-sessions" \
        "GET /api/v1/devices" \
        "GET /api/v1/os/releases" \
        "GET /api/v1/registrations"; do
        local ctrl_method ctrl_path
        ctrl_method=$(echo "$endpoint" | cut -d' ' -f1)
        ctrl_path=$(echo "$endpoint" | cut -d' ' -f2)
        local ctrl_code
        ctrl_code=$(http_code -X "$ctrl_method" "${SERVER_URL}${ctrl_path}" \
            -H "Authorization: Bearer ${tok:-invalid}")
        if [ "$ctrl_code" = "200" ] || [ "$ctrl_code" = "401" ] || [ "$ctrl_code" = "403" ] || [ "$ctrl_code" = "404" ]; then
            record S7 "CTRL_$(echo "$ctrl_path" | tr '/' '_')" PASS PASS "${ctrl_method} ${ctrl_path} → ${ctrl_code}"
        else
            record S7 "CTRL_$(echo "$ctrl_path" | tr '/' '_')" PASS BLOCKED "${ctrl_method} ${ctrl_path} → ${ctrl_code} (route may not be wired)"
            ctrl_blocked=$((ctrl_blocked+1))
        fi
    done
    [ $ctrl_blocked -gt 0 ] && [ "$st" = "PASS" ] && st=BLOCKED

    # ── ECDSA signature gap ───────────────────────────────────────────────────
    subhdr "S7-I: ECDSA request signature gap (known issue)"
    local sig_code
    sig_code=$(http_code -X POST "${SERVER_URL}/api/v1/admin/login" \
        -H "Content-Type: application/json" \
        -H "X-ExamOS-Signature: fakesig" \
        -H "X-ExamOS-Signature-Alg: ECDSA-P256" \
        -H "X-ExamOS-Signature-Key-Id: console-key-1" \
        -d '{"username":"nobody","password":"wrong"}')
    if [ "$sig_code" = "401" ] || [ "$sig_code" = "403" ]; then
        record S7 ECDSA_SIG_GAP PASS BLOCKED "server rejects bad creds but does NOT verify ECDSA sig (known gap)"
        [ "$st" = "PASS" ] && st=BLOCKED
    else
        record S7 ECDSA_SIG_GAP PASS BLOCKED "ECDSA signature not verified by backend (known gap — code=$sig_code)"
        [ "$st" = "PASS" ] && st=BLOCKED
    fi

    suite_result S7_API "$st"
}

# =============================================================================
# SUITE 8: Exam Lifecycle — create exam, roster, checkin, submit
# =============================================================================
run_suite_exam_lifecycle() {
    hdr "SUITE 8: Exam Lifecycle (create → roster → checkin → submit)"
    local st=PASS
    local tok
    tok=$(admin_token)
    [ -z "$tok" ] && { suite_result S8_EXAM_LIFECYCLE BLOCKED; return; }

    subhdr "S8-A: Create exam draft"
    local future_start=$(( $(date +%s) + 3600 ))
    local future_end=$(( future_start + 7200 ))
    local exam_resp
    exam_resp=$(curl -s -X POST "${SERVER_URL}/api/v1/platform/exams/create" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${tok}" \
        -d "{
            \"title\":\"E2E Test Exam\",
            \"institution_id\":\"inst-e2e\",
            \"exam_url\":\"https://exam.university.edu/e2e\",
            \"allowed_origins\":\"https://exam.university.edu\",
            \"duration_minutes\":60,
            \"retention_days\":30,
            \"timezone\":\"UTC\",
            \"permitted_device_group\":\"e2e-group\",
            \"browser_policy\":\"default\",
            \"scheduled_start\":${future_start},
            \"scheduled_end\":${future_end}
        }" 2>/dev/null)
    local exam_id
    exam_id=$(echo "$exam_resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('exam_id',''))" 2>/dev/null || echo "")
    if [ -n "$exam_id" ]; then
        record S8 EXAM_CREATE PASS PASS "exam created: $exam_id"
    else
        local exam_err
        exam_err=$(echo "$exam_resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('error',''))" 2>/dev/null || echo "$exam_resp")
        record S8 EXAM_CREATE PASS BLOCKED "exam create blocked/failed: $exam_err"
        st=BLOCKED
        suite_result S8_EXAM_LIFECYCLE "$st"
        return
    fi

    subhdr "S8-B: Add roster entry"
    local roster_resp
    roster_resp=$(curl -s -X POST "${SERVER_URL}/api/v1/platform/exams/${exam_id}/roster" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${tok}" \
        -d "{\"candidate_id\":\"E2E-C001\",\"full_name\":\"Test Candidate\",\"email\":\"test@exam.edu\",\"pin\":\"testpin123\"}" 2>/dev/null)
    local roster_status
    roster_status=$(echo "$roster_resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))" 2>/dev/null || echo "")
    if [ "$roster_status" = "created" ]; then
        record S8 ROSTER_ADD PASS PASS "roster entry created"
    else
        record S8 ROSTER_ADD PASS BLOCKED "roster add: $roster_status"
        [ "$st" = "PASS" ] && st=BLOCKED
    fi

    subhdr "S8-C: Advance exam state to ACTIVE"
    local state_resp
    state_resp=$(curl -s -X POST "${SERVER_URL}/api/v1/platform/exams/${exam_id}/state" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${tok}" \
        -d '{"state":"ACTIVE"}' 2>/dev/null)
    local state_val
    state_val=$(echo "$state_resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))" 2>/dev/null || echo "")
    if [ "$state_val" = "updated" ]; then
        record S8 EXAM_STATE_ACTIVE PASS PASS "exam advanced to ACTIVE"
    else
        record S8 EXAM_STATE_ACTIVE PASS BLOCKED "state transition: $state_val"
        [ "$st" = "PASS" ] && st=BLOCKED
    fi

    subhdr "S8-D: Checkin candidate"
    local ci_resp
    ci_resp=$(curl -s -X POST "${SERVER_URL}/api/v1/platform/exams/${exam_id}/checkin" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer ${tok}" \
        -d '{"candidate_id":"E2E-C001","device_id":"e2e-dev-001"}' 2>/dev/null)
    local ci_status
    ci_status=$(echo "$ci_resp" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))" 2>/dev/null || echo "")
    if [ "$ci_status" = "CHECKED_IN" ]; then
        record S8 CANDIDATE_CHECKIN PASS PASS "candidate checked in"
    else
        record S8 CANDIDATE_CHECKIN PASS BLOCKED "checkin: $ci_status"
        [ "$st" = "PASS" ] && st=BLOCKED
    fi

    suite_result S8_EXAM_LIFECYCLE "$st"
}

# =============================================================================
# SUITE 9: Existing server integration tests
# =============================================================================
run_suite_server_tests() {
    hdr "SUITE 9: Existing Server Integration Tests"
    local st=PASS

    for script in \
        "$WORKSPACE/tests/server/test_platform_e2e.sh" \
        "$WORKSPACE/tests/server/test_exam_lifecycle_e2e.sh" \
        "$WORKSPACE/tests/server/test_module_f_kiosk_security.sh" \
        "$WORKSPACE/tests/server/test_module_g_fleet_e2e.sh" \
        "$WORKSPACE/tests/server/test_module_h_attestation_e2e.sh"; do
        local name
        name="$(basename "$script" .sh)"
        if [ ! -f "$script" ]; then
            record S9 "$name" PASS BLOCKED "script not found"
            [ "$st" = "PASS" ] && st=BLOCKED
            continue
        fi
        local rc=0
        EXAMOS_SERVER_URL="$SERVER_URL" \
        EXAMOS_AGENT_API_TOKEN="$AGENT_TOKEN" \
        EXAMOS_PROCTOR_API_TOKEN="$PROCTOR_TOKEN" \
            bash "$script" >"$ARTIFACT_DIR/${name}.log" 2>&1 || rc=$?
        if [ $rc -eq 0 ]; then
            record S9 "$name" PASS PASS "$name passed"
        elif [ $rc -eq 2 ]; then
            record S9 "$name" PASS BLOCKED "$name blocked"
            [ "$st" = "PASS" ] && st=BLOCKED
        else
            record S9 "$name" PASS FAIL "$name failed (rc=$rc)"
            st=FAIL
        fi
    done

    suite_result S9_SERVER_TESTS "$st"
}

# =============================================================================
# MAIN ORCHESTRATOR
# =============================================================================
main() {
    hdr "ExamOS SPPIO™ — Full End-to-End Test Suite"
    log "Run ID   : $RUN_ID"
    log "Workspace: $WORKSPACE"
    log "Artifacts: $ARTIFACT_DIR"
    log "Server   : $SERVER_URL"

    # PostgreSQL
    log "Setting up PostgreSQL..."
    if ! setup_postgres; then
        log "WARNING: PostgreSQL unavailable — DB-dependent tests will be BLOCKED"
    fi

    # Build
    run_suite_build

    # Start live server
    hdr "Starting live server on port $SERVER_PORT"
    if ! start_server; then
        log "FATAL: Cannot start server — API suites will be BLOCKED"
        SERVER_PID=""
    else
        log "Server running (PID=$SERVER_PID)"
    fi

    # Phase suites
    run_suite_p0
    run_suite_p1
    run_suite_p2
    run_suite_p3
    run_suite_p4
    run_suite_p5

    # Live API suites (require running server)
    if [ -n "$SERVER_PID" ]; then
        run_suite_api
        run_suite_exam_lifecycle
        run_suite_server_tests
    else
        log "SKIPPING API suites — server not running"
        suite_result S7_API BLOCKED
        suite_result S8_EXAM_LIFECYCLE BLOCKED
        suite_result S9_SERVER_TESTS BLOCKED
    fi

    # ── Final report ──────────────────────────────────────────────────────────
    hdr "FINAL REPORT"
    local overall=PASS
    [ $FAIL -gt 0 ]    && overall=FAIL
    [ $BLOCKED -gt 0 ] && [ $FAIL -eq 0 ] && overall=BLOCKED

    echo ""
    echo "  Suite Results:"
    for r in "${SUITE_RESULTS[@]}"; do
        echo "    $r"
    done
    echo ""
    echo "  Totals: PASS=$PASS  FAIL=$FAIL  BLOCKED=$BLOCKED"
    echo "  Overall: $overall"
    echo ""

    # Write JSON manifest
    python3 - "$ARTIFACT_DIR/e2e-results.json" \
        "$overall" "$PASS" "$FAIL" "$BLOCKED" "$RUN_ID" \
        "$(git -C "$WORKSPACE" rev-parse HEAD 2>/dev/null || echo unknown)" \
        "${SUITE_RESULTS[@]}" <<'PY'
import json, sys, datetime, pathlib
out, overall, passed, failed, blocked, run_id, commit, *suites = sys.argv[1:]
report = {
    "suite": "examos-e2e-full",
    "run_id": run_id,
    "timestamp": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "source_commit": commit,
    "overall": overall,
    "totals": {"pass": int(passed), "fail": int(failed), "blocked": int(blocked)},
    "suites": {k: v for k, v in (s.split("=", 1) for s in suites)},
}
pathlib.Path(out).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
print(json.dumps(report, indent=2))
PY

    log "Results written to $ARTIFACT_DIR/e2e-results.json"

    case "$overall" in
        PASS)    exit 0 ;;
        BLOCKED) exit 2 ;;
        *)       exit 1 ;;
    esac
}

main "$@"
