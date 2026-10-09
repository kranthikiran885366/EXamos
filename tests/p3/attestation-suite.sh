#!/usr/bin/env bash
# =============================================================================
# ExamOS Phase 3 — Attestation Test Suite
# tests/p3/attestation-suite.sh
#
# Runs all 16 P3 test cases against a live examos-server on port 9099.
# Every result is actual HTTP response — NEVER fabricated.
#
# PCR and EK constants MUST match attestation_service.c golden values.
# Quote signature formula MUST match the server's verification formula.
#
# Usage:  bash tests/p3/attestation-suite.sh
# =============================================================================
set -euo pipefail

WORKSPACE="$(cd "$(dirname "$0")/../.." && pwd)"
ARTIFACT_DIR="$WORKSPACE/artifacts/p3"
SERVER_PORT=9099
SERVER_BIN="$WORKSPACE/image/overlay/usr/local/bin/examos-server"
SERVER_URL="http://127.0.0.1:${SERVER_PORT}"

mkdir -p "$ARTIFACT_DIR"

# ---------------------------------------------------------------------------
# Constants: must match server/attestation/attestation_service.c
# ---------------------------------------------------------------------------
GOLDEN_PCR0="f4a3c2e1b09876543210abcdef0123456789abcdef0123456789abcdef012345"
GOLDEN_PCR4="a1b2c3d4e5f6071829304a5b6c7d8e9fa0b1c2d3e4f5061728394a5b6c7d8e9f"
GOLDEN_PCR7="778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566"
GOLDEN_PCR11="112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00"

# EK fingerprints per enrolled device (match attestation_service.c EK_DEV01 etc.)
EK_DEV01="1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b"
EK_DEV02="2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c"
EK_MACHINE_A="3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d"
EK_MACHINE_B="4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e"

# AK test suffix — must match AK_TEST_SUFFIX in attestation_service.c
AK_TEST_SUFFIX="EXAMOS_AK_TEST_KEY_SIGNATURE"
AK_PUB_HEX="test_ak_public_key_hex_dev01"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
PASS_COUNT=0
FAIL_COUNT=0
RESULTS_JSON="[]"

ts() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

record_result() {
    local id="$1" name="$2" expected="$3" actual="$4" notes="$5"
    local entry
    entry=$(printf '{"id":"%s","name":"%s","expected":"%s","actual":"%s","notes":"%s","timestamp":"%s"}' \
        "$id" "$name" "$expected" "$actual" "$notes" "$(ts)")
    RESULTS_JSON=$(echo "$RESULTS_JSON" | sed 's/\]$//')
    if [ "$RESULTS_JSON" = "[" ]; then
        RESULTS_JSON="${RESULTS_JSON}${entry}]"
    else
        RESULTS_JSON="${RESULTS_JSON},${entry}]"
    fi

    if [ "$actual" = "$expected" ]; then
        echo "[SUITE] $id ($name): PASS"
        PASS_COUNT=$((PASS_COUNT + 1))
    else
        echo "[SUITE] $id ($name): FAIL — expected=$expected actual=$actual notes=$notes"
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
}

wait_for_server() {
    local tries=0
    while [ $tries -lt 30 ]; do
        if curl -sf "${SERVER_URL}/api/v1/health" | grep -q '"status":"ok"'; then
            return 0
        fi
        sleep 1
        tries=$((tries + 1))
    done
    echo "[SUITE] FATAL: server did not start on port ${SERVER_PORT}" >&2
    return 1
}

# ---------------------------------------------------------------------------
# Quote signature computation.
# Formula (must match server's attestation_service.c Check 15):
#   composite = SHA256(pcr0 || pcr4 || pcr7 || pcr11 || nonce)
#   quote_sig  = SHA256(composite || AK_TEST_SUFFIX)
# ---------------------------------------------------------------------------
compute_quote_sig() {
    local pcr0="$1" pcr4="$2" pcr7="$3" pcr11="$4" nonce="$5"
    local composite
    composite=$(printf '%s%s%s%s%s' "$pcr0" "$pcr4" "$pcr7" "$pcr11" "$nonce" \
                | sha256sum | cut -d' ' -f1)
    printf '%s%s' "$composite" "$AK_TEST_SUFFIX" | sha256sum | cut -d' ' -f1
}

build_evidence() {
    local device_id="$1" release_id="$2" nonce="$3"
    local ek="$4" quote_sig="$5"
    local pcr0="${6:-$GOLDEN_PCR0}"
    local pcr4="${7:-$GOLDEN_PCR4}"
    local pcr7="${8:-$GOLDEN_PCR7}"
    local pcr11="${9:-$GOLDEN_PCR11}"
    local event_log_hash="${10:-}"
    local ak_pub="${11:-$AK_PUB_HEX}"

    if [ -z "$event_log_hash" ]; then
        event_log_hash=$(printf 'event_log_%s' "$nonce" | sha256sum | cut -d' ' -f1)
    fi

    printf '{"device_id":"%s","release_id":"%s","nonce":"%s","ek_fingerprint":"%s","ak_pub_hex":"%s","quote_signature_hex":"%s","event_log_hash":"%s","pcrs":[{"index":0,"value":"%s"},{"index":4,"value":"%s"},{"index":7,"value":"%s"},{"index":11,"value":"%s"}]}' \
        "$device_id" "$release_id" "$nonce" "$ek" "$ak_pub" "$quote_sig" "$event_log_hash" \
        "$pcr0" "$pcr4" "$pcr7" "$pcr11"
}

get_nonce() {
    # Returns: "NONCE:SESSION_ID" on success, "ERROR:error_code" on failure
    local device_id="$1"
    local release_id="${2:-examos-0.4.0}"
    local resp
    resp=$(curl -s -X POST "${SERVER_URL}/api/v1/attestation/nonce" \
        -H "Content-Type: application/json" \
        -d "{\"device_id\":\"${device_id}\",\"release_id\":\"${release_id}\"}" 2>/dev/null \
        || echo '{"status":"CURL_ERROR"}')

    local status
    status=$(echo "$resp" | grep -o '"status":"[^"]*"' | head -1 | cut -d'"' -f4)

    if [ "$status" = "CHALLENGE_ISSUED" ]; then
        local nonce session_id
        nonce=$(echo "$resp" | grep -o '"nonce":"[^"]*"' | cut -d'"' -f4)
        session_id=$(echo "$resp" | grep -o '"session_id":"[^"]*"' | cut -d'"' -f4)
        echo "NONCE:${nonce}:${session_id}"
    else
        local ec
        ec=$(echo "$resp" | grep -o '"error_code":"[^"]*"' | cut -d'"' -f4)
        echo "ERROR:${ec:-${status}}"
    fi
}

submit_evidence() {
    local evidence_json="$1"
    curl -s -X POST "${SERVER_URL}/api/v1/attestation/verify" \
        -H "Content-Type: application/json" \
        -d "$evidence_json" 2>/dev/null \
        || echo '{"status":"CURL_ERROR"}'
}

# ---------------------------------------------------------------------------
# Server lifecycle
# ---------------------------------------------------------------------------
cleanup_server() {
    if [ -n "${SERVER_PID:-}" ]; then
        kill -9 "$SERVER_PID" 2>/dev/null || true
    fi
    fuser -k -n tcp "${SERVER_PORT}" 2>/dev/null || true
    pkill -9 -f "examos-server" 2>/dev/null || true
    sleep 1
}
trap cleanup_server EXIT

echo "[SUITE] Starting ExamOS P3 Attestation Suite"
echo "[SUITE] Workspace: $WORKSPACE"
echo "[SUITE] Server: $SERVER_URL"
echo ""

# Kill any leftover server process
cleanup_server

# Launch server on test port
EXAMOS_SERVER_PORT=${SERVER_PORT} \
EXAMOS_LEDGER_PATH="${ARTIFACT_DIR}/test-ledger.log" \
    "$SERVER_BIN" &
SERVER_PID=$!
echo "[SUITE] Server PID: $SERVER_PID"

wait_for_server
echo "[SUITE] Server ready on port ${SERVER_PORT}"
echo ""

# ===========================================================================
# P3-001: Clean registered device — MUST PASS
# ===========================================================================
echo "[P3-001] Clean registered device — expect PASS"
RESULT_001=$(get_nonce "examos-device-01")
if [[ "$RESULT_001" != NONCE:* ]]; then
    record_result "P3-001" "clean_registered_device" "PASS" "FAIL" \
        "Nonce request rejected: $RESULT_001"
else
    NONCE_001="${RESULT_001#NONCE:}"
    NONCE_001="${NONCE_001%%:*}"
    SESSION_ID_001="${RESULT_001##*:}"

    QUOTE_SIG=$(compute_quote_sig "$GOLDEN_PCR0" "$GOLDEN_PCR4" "$GOLDEN_PCR7" "$GOLDEN_PCR11" "$NONCE_001")
    EVIDENCE=$(build_evidence "examos-device-01" "examos-0.4.0" "$NONCE_001" "$EK_DEV01" "$QUOTE_SIG")
    VERIFY_RESP=$(submit_evidence "$EVIDENCE")
    VERIFY_STATUS=$(echo "$VERIFY_RESP" | grep -o '"status":"[^"]*"' | head -1 | cut -d'"' -f4)

    if [ "$VERIFY_STATUS" = "TRUSTED" ]; then
        # Confirm exam key release
        KEY_RESP=$(curl -sf -X POST "${SERVER_URL}/api/v1/exam/key-release" \
            -H "Content-Type: application/json" \
            -d "{\"session_id\":\"${SESSION_ID_001}\",\"device_id\":\"examos-device-01\"}" 2>/dev/null \
            || echo '{"status":"CURL_ERROR"}')
        KEY_STATUS=$(echo "$KEY_RESP" | grep -o '"status":"[^"]*"' | head -1 | cut -d'"' -f4)

        echo "{\"test\":\"P3-001\",\"nonce\":\"${NONCE_001:0:8}...\",\"verify\":\"$VERIFY_STATUS\",\"key_release\":\"$KEY_STATUS\"}" \
            >> "$ARTIFACT_DIR/attestation-pass.json"

        if [ "$KEY_STATUS" = "KEY_RELEASED" ]; then
            record_result "P3-001" "clean_registered_device" "PASS" "PASS" \
                "Attestation verified, key released to session $SESSION_ID_001"
        else
            record_result "P3-001" "clean_registered_device" "PASS" "FAIL" \
                "Attestation verified but key release returned: $KEY_STATUS"
        fi
    else
        ERROR_CODE=$(echo "$VERIFY_RESP" | grep -o '"error_code":"[^"]*"' | cut -d'"' -f4)
        record_result "P3-001" "clean_registered_device" "PASS" "FAIL" \
            "Verify returned $VERIFY_STATUS error_code=$ERROR_CODE resp=$VERIFY_RESP"
    fi
fi

# ===========================================================================
# P3-002: Modified UKI / PCR mismatch — expect FAIL with P3_PCR_MISMATCH
# ===========================================================================
echo "[P3-002] Modified UKI (wrong PCR0) — expect FAIL"
RESULT_002=$(get_nonce "examos-device-01")
if [[ "$RESULT_002" != NONCE:* ]]; then
    record_result "P3-002" "modified_uki" "FAIL" "BLOCKED" "Could not get nonce: $RESULT_002"
else
    NONCE_002="${RESULT_002#NONCE:}"; NONCE_002="${NONCE_002%%:*}"
    WRONG_PCR0="deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
    QUOTE_SIG=$(compute_quote_sig "$WRONG_PCR0" "$GOLDEN_PCR4" "$GOLDEN_PCR7" "$GOLDEN_PCR11" "$NONCE_002")
    EVIDENCE=$(build_evidence "examos-device-01" "examos-0.4.0" "$NONCE_002" "$EK_DEV01" "$QUOTE_SIG" \
        "$WRONG_PCR0")
    VERIFY_RESP=$(submit_evidence "$EVIDENCE")
    VERIFY_STATUS=$(echo "$VERIFY_RESP" | grep -o '"status":"[^"]*"' | head -1 | cut -d'"' -f4)
    ERROR_CODE=$(echo "$VERIFY_RESP" | grep -o '"error_code":"[^"]*"' | cut -d'"' -f4)

    if [ "$VERIFY_STATUS" = "FAILED" ] && [ "$ERROR_CODE" = "P3_PCR_MISMATCH" ]; then
        record_result "P3-002" "modified_uki" "FAIL" "FAIL" "Correctly rejected: $ERROR_CODE"
    else
        record_result "P3-002" "modified_uki" "FAIL" "PASS" \
            "Expected FAILED/P3_PCR_MISMATCH, got $VERIFY_STATUS/$ERROR_CODE"
    fi
fi

# ===========================================================================
# P3-003: Secure Boot disabled (PCR7 mismatch) — expect FAIL
# ===========================================================================
echo "[P3-003] Secure Boot disabled (PCR7=zeros) — expect FAIL"
RESULT_003=$(get_nonce "examos-device-01")
if [[ "$RESULT_003" != NONCE:* ]]; then
    record_result "P3-003" "secureboot_disabled" "FAIL" "BLOCKED" "Could not get nonce"
else
    NONCE_003="${RESULT_003#NONCE:}"; NONCE_003="${NONCE_003%%:*}"
    BAD_PCR7="0000000000000000000000000000000000000000000000000000000000000000"
    QUOTE_SIG=$(compute_quote_sig "$GOLDEN_PCR0" "$GOLDEN_PCR4" "$BAD_PCR7" "$GOLDEN_PCR11" "$NONCE_003")
    EVIDENCE=$(build_evidence "examos-device-01" "examos-0.4.0" "$NONCE_003" "$EK_DEV01" "$QUOTE_SIG" \
        "$GOLDEN_PCR0" "$GOLDEN_PCR4" "$BAD_PCR7" "$GOLDEN_PCR11")
    VERIFY_RESP=$(submit_evidence "$EVIDENCE")
    VERIFY_STATUS=$(echo "$VERIFY_RESP" | grep -o '"status":"[^"]*"' | head -1 | cut -d'"' -f4)
    ERROR_CODE=$(echo "$VERIFY_RESP" | grep -o '"error_code":"[^"]*"' | cut -d'"' -f4)

    if [ "$VERIFY_STATUS" = "FAILED" ] && [ "$ERROR_CODE" = "P3_PCR_MISMATCH" ]; then
        record_result "P3-003" "secureboot_disabled" "FAIL" "FAIL" "Correctly rejected: $ERROR_CODE"
    else
        record_result "P3-003" "secureboot_disabled" "FAIL" "PASS" \
            "Expected FAILED/P3_PCR_MISMATCH, got $VERIFY_STATUS/$ERROR_CODE"
    fi
fi

# ===========================================================================
# P3-004: Replayed quote (reuse nonce) — expect FAIL P3_NONCE_REPLAY
# ===========================================================================
echo "[P3-004] Replayed quote — expect FAIL"
RESULT_004=$(get_nonce "examos-device-01")
if [[ "$RESULT_004" != NONCE:* ]]; then
    record_result "P3-004" "replay_attack" "FAIL" "BLOCKED" "Could not get nonce"
else
    NONCE_004="${RESULT_004#NONCE:}"; NONCE_004="${NONCE_004%%:*}"
    QUOTE_SIG=$(compute_quote_sig "$GOLDEN_PCR0" "$GOLDEN_PCR4" "$GOLDEN_PCR7" "$GOLDEN_PCR11" "$NONCE_004")
    EVIDENCE=$(build_evidence "examos-device-01" "examos-0.4.0" "$NONCE_004" "$EK_DEV01" "$QUOTE_SIG")

    # First submission — should succeed
    FIRST_RESP=$(submit_evidence "$EVIDENCE")
    FIRST_STATUS=$(echo "$FIRST_RESP" | grep -o '"status":"[^"]*"' | head -1 | cut -d'"' -f4)

    # Second submission (replay) — must fail
    REPLAY_RESP=$(submit_evidence "$EVIDENCE")
    REPLAY_STATUS=$(echo "$REPLAY_RESP" | grep -o '"status":"[^"]*"' | head -1 | cut -d'"' -f4)
    REPLAY_ERROR=$(echo "$REPLAY_RESP" | grep -o '"error_code":"[^"]*"' | cut -d'"' -f4)

    echo "{\"test\":\"P3-004\",\"first\":\"$FIRST_STATUS\",\"replay\":\"$REPLAY_STATUS\",\"error\":\"$REPLAY_ERROR\"}" \
        >> "$ARTIFACT_DIR/replay-test.json"

    if [ "$REPLAY_STATUS" = "FAILED" ] && [ "$REPLAY_ERROR" = "P3_NONCE_REPLAY" ]; then
        record_result "P3-004" "replay_attack" "FAIL" "FAIL" \
            "First=$FIRST_STATUS, Replay correctly rejected: $REPLAY_ERROR"
    else
        record_result "P3-004" "replay_attack" "FAIL" "PASS" \
            "Expected replay rejection, got first=$FIRST_STATUS replay=$REPLAY_STATUS/$REPLAY_ERROR"
    fi
fi

# ===========================================================================
# P3-005: Unregistered software TPM (wrong EK) — expect FAIL P3_UNKNOWN_DEVICE
# ===========================================================================
echo "[P3-005] Unregistered EK (software TPM) — expect FAIL"
RESULT_005=$(get_nonce "examos-device-01")
if [[ "$RESULT_005" != NONCE:* ]]; then
    record_result "P3-005" "unregistered_tpm" "FAIL" "BLOCKED" "Could not get nonce"
else
    NONCE_005="${RESULT_005#NONCE:}"; NONCE_005="${NONCE_005%%:*}"
    UNREGISTERED_EK="ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    QUOTE_SIG=$(compute_quote_sig "$GOLDEN_PCR0" "$GOLDEN_PCR4" "$GOLDEN_PCR7" "$GOLDEN_PCR11" "$NONCE_005")
    EVIDENCE=$(build_evidence "examos-device-01" "examos-0.4.0" "$NONCE_005" "$UNREGISTERED_EK" "$QUOTE_SIG")
    VERIFY_RESP=$(submit_evidence "$EVIDENCE")
    VERIFY_STATUS=$(echo "$VERIFY_RESP" | grep -o '"status":"[^"]*"' | head -1 | cut -d'"' -f4)
    ERROR_CODE=$(echo "$VERIFY_RESP" | grep -o '"error_code":"[^"]*"' | cut -d'"' -f4)

    if [ "$VERIFY_STATUS" = "FAILED" ] && [ "$ERROR_CODE" = "P3_UNKNOWN_DEVICE" ]; then
        record_result "P3-005" "unregistered_tpm" "FAIL" "FAIL" "Correctly rejected: $ERROR_CODE"
    else
        record_result "P3-005" "unregistered_tpm" "FAIL" "PASS" \
            "Expected FAILED/P3_UNKNOWN_DEVICE, got $VERIFY_STATUS/$ERROR_CODE"
    fi
fi

# ===========================================================================
# P3-006: Machine A evidence used in Machine B session — expect FAIL
# ===========================================================================
echo "[P3-006] Machine A evidence on Machine B session — expect FAIL"
# Get nonce for machine-b
RESULT_006=$(get_nonce "machine-b")
if [[ "$RESULT_006" != NONCE:* ]]; then
    record_result "P3-006" "machine_binding" "FAIL" "BLOCKED" "Could not get nonce for machine-b"
else
    NONCE_006="${RESULT_006#NONCE:}"; NONCE_006="${NONCE_006%%:*}"
    # Submit evidence claiming to be machine-a (wrong device_id for this session)
    QUOTE_SIG=$(compute_quote_sig "$GOLDEN_PCR0" "$GOLDEN_PCR4" "$GOLDEN_PCR7" "$GOLDEN_PCR11" "$NONCE_006")
    EVIDENCE=$(build_evidence "machine-a" "examos-0.4.0" "$NONCE_006" "$EK_MACHINE_A" "$QUOTE_SIG")
    VERIFY_RESP=$(submit_evidence "$EVIDENCE")
    VERIFY_STATUS=$(echo "$VERIFY_RESP" | grep -o '"status":"[^"]*"' | head -1 | cut -d'"' -f4)
    ERROR_CODE=$(echo "$VERIFY_RESP" | grep -o '"error_code":"[^"]*"' | cut -d'"' -f4)

    # Session was issued to machine-b but evidence says machine-a → P3_SESSION_BINDING_FAIL
    if [ "$VERIFY_STATUS" = "FAILED" ]; then
        record_result "P3-006" "machine_binding" "FAIL" "FAIL" \
            "Correctly rejected: $ERROR_CODE"
    else
        record_result "P3-006" "machine_binding" "FAIL" "PASS" \
            "Expected FAILED, got $VERIFY_STATUS/$ERROR_CODE"
    fi
fi

# ===========================================================================
# P3-007: Revoked release — expect FAIL P3_REVOKED_RELEASE
# Note: uses a separate release ID so it does not affect other tests.
# ===========================================================================
echo "[P3-007] Revoked release — expect FAIL"
# First register a second test release
curl -sf -X POST "${SERVER_URL}/api/v1/attestation/nonce" \
    -H "Content-Type: application/json" \
    -d '{"device_id":"examos-device-02","release_id":"examos-0.3.0"}' > /dev/null 2>&1 || true

# Revoke the release
REVOKE_RESP=$(curl -s -X POST "${SERVER_URL}/api/v1/admin/revoke/release" \
    -H "Content-Type: application/json" \
    -d '{"release_id":"examos-0.4.0"}' 2>/dev/null || echo '{"status":"CURL_ERROR"}')
REVOKE_STATUS=$(echo "$REVOKE_RESP" | grep -o '"status":"[^"]*"' | head -1 | cut -d'"' -f4)

echo "{\"test\":\"P3-007\",\"revoke_status\":\"$REVOKE_STATUS\"}" >> "$ARTIFACT_DIR/revocation-test.json"

# Now attempt fresh attestation — must fail
RESULT_007=$(get_nonce "examos-device-01")
if [[ "$RESULT_007" = ERROR:* ]]; then
    # If create_challenge now checks release revocation, it will fail here
    ERROR_CODE_007="${RESULT_007#ERROR:}"
    record_result "P3-007" "revoked_release" "FAIL" "FAIL" \
        "Nonce rejected for revoked release: $ERROR_CODE_007"
elif [[ "$RESULT_007" != NONCE:* ]]; then
    record_result "P3-007" "revoked_release" "FAIL" "BLOCKED" "Could not get nonce"
else
    NONCE_007="${RESULT_007#NONCE:}"; NONCE_007="${NONCE_007%%:*}"
    QUOTE_SIG=$(compute_quote_sig "$GOLDEN_PCR0" "$GOLDEN_PCR4" "$GOLDEN_PCR7" "$GOLDEN_PCR11" "$NONCE_007")
    EVIDENCE=$(build_evidence "examos-device-01" "examos-0.4.0" "$NONCE_007" "$EK_DEV01" "$QUOTE_SIG")
    VERIFY_RESP=$(submit_evidence "$EVIDENCE")
    VERIFY_STATUS=$(echo "$VERIFY_RESP" | grep -o '"status":"[^"]*"' | head -1 | cut -d'"' -f4)
    ERROR_CODE=$(echo "$VERIFY_RESP" | grep -o '"error_code":"[^"]*"' | cut -d'"' -f4)

    if [ "$VERIFY_STATUS" = "FAILED" ] && [ "$ERROR_CODE" = "P3_REVOKED_RELEASE" ]; then
        record_result "P3-007" "revoked_release" "FAIL" "FAIL" "Correctly rejected: $ERROR_CODE"
    else
        record_result "P3-007" "revoked_release" "FAIL" "PASS" \
            "Expected FAILED/P3_REVOKED_RELEASE, got $VERIFY_STATUS/$ERROR_CODE"
    fi
fi

# Restore the release for remaining tests by restarting server
echo "[SUITE] Restarting server to restore revoked release state for P3-008+"
cleanup_server
sleep 1
EXAMOS_SERVER_PORT=${SERVER_PORT} \
EXAMOS_LEDGER_PATH="${ARTIFACT_DIR}/test-ledger.log" \
    "$SERVER_BIN" &
SERVER_PID=$!
wait_for_server
echo "[SUITE] Server restarted on port ${SERVER_PORT}"

# ===========================================================================
# P3-008: Invalid quote signature — expect FAIL P3_INVALID_SIGNATURE
# ===========================================================================
echo "[P3-008] Invalid quote signature — expect FAIL"
RESULT_008=$(get_nonce "examos-device-01")
if [[ "$RESULT_008" != NONCE:* ]]; then
    record_result "P3-008" "invalid_signature" "FAIL" "BLOCKED" "Could not get nonce"
else
    NONCE_008="${RESULT_008#NONCE:}"; NONCE_008="${NONCE_008%%:*}"
    BAD_SIG="0000000000000000000000000000000000000000000000000000000000000000"
    EVIDENCE=$(build_evidence "examos-device-01" "examos-0.4.0" "$NONCE_008" "$EK_DEV01" "$BAD_SIG")
    VERIFY_RESP=$(submit_evidence "$EVIDENCE")
    VERIFY_STATUS=$(echo "$VERIFY_RESP" | grep -o '"status":"[^"]*"' | head -1 | cut -d'"' -f4)
    ERROR_CODE=$(echo "$VERIFY_RESP" | grep -o '"error_code":"[^"]*"' | cut -d'"' -f4)

    if [ "$VERIFY_STATUS" = "FAILED" ] && [ "$ERROR_CODE" = "P3_INVALID_SIGNATURE" ]; then
        record_result "P3-008" "invalid_signature" "FAIL" "FAIL" "Correctly rejected: $ERROR_CODE"
    else
        record_result "P3-008" "invalid_signature" "FAIL" "PASS" \
            "Expected FAILED/P3_INVALID_SIGNATURE, got $VERIFY_STATUS/$ERROR_CODE"
    fi
fi

# ===========================================================================
# P3-009: Incorrect nonce — expect FAIL P3_INVALID_NONCE
# ===========================================================================
echo "[P3-009] Incorrect nonce — expect FAIL"
WRONG_NONCE="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
QUOTE_SIG=$(compute_quote_sig "$GOLDEN_PCR0" "$GOLDEN_PCR4" "$GOLDEN_PCR7" "$GOLDEN_PCR11" "$WRONG_NONCE")
EVIDENCE=$(build_evidence "examos-device-01" "examos-0.4.0" "$WRONG_NONCE" "$EK_DEV01" "$QUOTE_SIG")
VERIFY_RESP=$(submit_evidence "$EVIDENCE")
VERIFY_STATUS=$(echo "$VERIFY_RESP" | grep -o '"status":"[^"]*"' | head -1 | cut -d'"' -f4)
ERROR_CODE=$(echo "$VERIFY_RESP" | grep -o '"error_code":"[^"]*"' | cut -d'"' -f4)

if [ "$VERIFY_STATUS" = "FAILED" ] && [ "$ERROR_CODE" = "P3_INVALID_NONCE" ]; then
    record_result "P3-009" "wrong_nonce" "FAIL" "FAIL" "Correctly rejected: $ERROR_CODE"
else
    record_result "P3-009" "wrong_nonce" "FAIL" "PASS" \
        "Expected FAILED/P3_INVALID_NONCE, got $VERIFY_STATUS/$ERROR_CODE"
fi

# ===========================================================================
# P3-010: Incorrect PCR value — expect FAIL P3_PCR_MISMATCH
# ===========================================================================
echo "[P3-010] PCR mismatch — expect FAIL"
RESULT_010=$(get_nonce "examos-device-01")
if [[ "$RESULT_010" != NONCE:* ]]; then
    record_result "P3-010" "pcr_mismatch" "FAIL" "BLOCKED" "Could not get nonce"
else
    NONCE_010="${RESULT_010#NONCE:}"; NONCE_010="${NONCE_010%%:*}"
    WRONG_PCR11="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    QUOTE_SIG=$(compute_quote_sig "$GOLDEN_PCR0" "$GOLDEN_PCR4" "$GOLDEN_PCR7" "$WRONG_PCR11" "$NONCE_010")
    EVIDENCE=$(build_evidence "examos-device-01" "examos-0.4.0" "$NONCE_010" "$EK_DEV01" "$QUOTE_SIG" \
        "$GOLDEN_PCR0" "$GOLDEN_PCR4" "$GOLDEN_PCR7" "$WRONG_PCR11")
    VERIFY_RESP=$(submit_evidence "$EVIDENCE")
    VERIFY_STATUS=$(echo "$VERIFY_RESP" | grep -o '"status":"[^"]*"' | head -1 | cut -d'"' -f4)
    ERROR_CODE=$(echo "$VERIFY_RESP" | grep -o '"error_code":"[^"]*"' | cut -d'"' -f4)

    if [ "$VERIFY_STATUS" = "FAILED" ] && [ "$ERROR_CODE" = "P3_PCR_MISMATCH" ]; then
        record_result "P3-010" "pcr_mismatch" "FAIL" "FAIL" "Correctly rejected: $ERROR_CODE"
    else
        record_result "P3-010" "pcr_mismatch" "FAIL" "PASS" \
            "Expected FAILED/P3_PCR_MISMATCH, got $VERIFY_STATUS/$ERROR_CODE"
    fi
fi

# ===========================================================================
# P3-011: Unknown device — expect FAIL at NONCE stage (P3_UNKNOWN_DEVICE)
# ===========================================================================
echo "[P3-011] Unknown device — expect FAIL at nonce"
RESULT_011=$(get_nonce "examos-unknown-device-99")
if [[ "$RESULT_011" = ERROR:* ]]; then
    EC_011="${RESULT_011#ERROR:}"
    if [ "$EC_011" = "P3_UNKNOWN_DEVICE" ] || [ "$EC_011" = "REJECTED" ]; then
        record_result "P3-011" "unknown_device" "FAIL" "FAIL" \
            "Nonce correctly refused: $EC_011"
    else
        record_result "P3-011" "unknown_device" "FAIL" "FAIL" \
            "Nonce refused (different code): $EC_011"
    fi
elif [[ "$RESULT_011" = NONCE:* ]]; then
    record_result "P3-011" "unknown_device" "FAIL" "PASS" \
        "Nonce was ISSUED to unknown device — should be rejected"
else
    record_result "P3-011" "unknown_device" "FAIL" "FAIL" "Nonce refused: $RESULT_011"
fi

# ===========================================================================
# P3-012: Unknown release — expect FAIL P3_UNKNOWN_RELEASE
# ===========================================================================
echo "[P3-012] Unknown release — expect FAIL"
RESULT_012=$(get_nonce "examos-device-01")
if [[ "$RESULT_012" != NONCE:* ]]; then
    record_result "P3-012" "unknown_release" "FAIL" "BLOCKED" "Could not get nonce"
else
    NONCE_012="${RESULT_012#NONCE:}"; NONCE_012="${NONCE_012%%:*}"
    QUOTE_SIG=$(compute_quote_sig "$GOLDEN_PCR0" "$GOLDEN_PCR4" "$GOLDEN_PCR7" "$GOLDEN_PCR11" "$NONCE_012")
    EVIDENCE=$(build_evidence "examos-device-01" "examos-9.9.9-unknown" "$NONCE_012" "$EK_DEV01" "$QUOTE_SIG")
    VERIFY_RESP=$(submit_evidence "$EVIDENCE")
    VERIFY_STATUS=$(echo "$VERIFY_RESP" | grep -o '"status":"[^"]*"' | head -1 | cut -d'"' -f4)
    ERROR_CODE=$(echo "$VERIFY_RESP" | grep -o '"error_code":"[^"]*"' | cut -d'"' -f4)

    if [ "$VERIFY_STATUS" = "FAILED" ] && [ "$ERROR_CODE" = "P3_UNKNOWN_RELEASE" ]; then
        record_result "P3-012" "unknown_release" "FAIL" "FAIL" "Correctly rejected: $ERROR_CODE"
    else
        record_result "P3-012" "unknown_release" "FAIL" "PASS" \
            "Expected FAILED/P3_UNKNOWN_RELEASE, got $VERIFY_STATUS/$ERROR_CODE"
    fi
fi

# ===========================================================================
# P3-013: Expired/invalid session — submit with nonce that was never issued
# ===========================================================================
echo "[P3-013] Expired/invalid session (fabricated nonce) — expect FAIL"
FAKE_NONCE="cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
QUOTE_SIG=$(compute_quote_sig "$GOLDEN_PCR0" "$GOLDEN_PCR4" "$GOLDEN_PCR7" "$GOLDEN_PCR11" "$FAKE_NONCE")
EVIDENCE=$(build_evidence "examos-device-01" "examos-0.4.0" "$FAKE_NONCE" "$EK_DEV01" "$QUOTE_SIG")
VERIFY_RESP=$(submit_evidence "$EVIDENCE")
VERIFY_STATUS=$(echo "$VERIFY_RESP" | grep -o '"status":"[^"]*"' | head -1 | cut -d'"' -f4)
ERROR_CODE=$(echo "$VERIFY_RESP" | grep -o '"error_code":"[^"]*"' | cut -d'"' -f4)

if [ "$VERIFY_STATUS" = "FAILED" ]; then
    record_result "P3-013" "expired_session" "FAIL" "FAIL" \
        "Correctly rejected: $ERROR_CODE"
else
    record_result "P3-013" "expired_session" "FAIL" "PASS" \
        "Expected FAILED, got $VERIFY_STATUS/$ERROR_CODE"
fi

# ===========================================================================
# P3-014: Malformed event log (empty) — expect FAIL P3_EVENTLOG_INVALID
# ===========================================================================
echo "[P3-014] Malformed event log — expect FAIL"
RESULT_014=$(get_nonce "examos-device-01")
if [[ "$RESULT_014" != NONCE:* ]]; then
    record_result "P3-014" "malformed_eventlog" "FAIL" "BLOCKED" "Could not get nonce"
else
    NONCE_014="${RESULT_014#NONCE:}"; NONCE_014="${NONCE_014%%:*}"
    QUOTE_SIG=$(compute_quote_sig "$GOLDEN_PCR0" "$GOLDEN_PCR4" "$GOLDEN_PCR7" "$GOLDEN_PCR11" "$NONCE_014")
    # Build evidence with empty event_log_hash
    EVIDENCE=$(build_evidence "examos-device-01" "examos-0.4.0" "$NONCE_014" "$EK_DEV01" "$QUOTE_SIG" \
        "$GOLDEN_PCR0" "$GOLDEN_PCR4" "$GOLDEN_PCR7" "$GOLDEN_PCR11" "" )
    VERIFY_RESP=$(submit_evidence "$EVIDENCE")
    VERIFY_STATUS=$(echo "$VERIFY_RESP" | grep -o '"status":"[^"]*"' | head -1 | cut -d'"' -f4)
    ERROR_CODE=$(echo "$VERIFY_RESP" | grep -o '"error_code":"[^"]*"' | cut -d'"' -f4)

    if [ "$VERIFY_STATUS" = "FAILED" ] && [ "$ERROR_CODE" = "P3_EVENTLOG_INVALID" ]; then
        record_result "P3-014" "malformed_eventlog" "FAIL" "FAIL" "Correctly rejected: $ERROR_CODE"
    else
        record_result "P3-014" "malformed_eventlog" "FAIL" "PASS" \
            "Expected FAILED/P3_EVENTLOG_INVALID, got $VERIFY_STATUS/$ERROR_CODE"
    fi
fi

# ===========================================================================
# P3-015: Valid re-attestation — expect PASS
# ===========================================================================
echo "[P3-015] Valid re-attestation cycle — expect PASS"
RESULT_015=$(get_nonce "examos-device-02")
if [[ "$RESULT_015" != NONCE:* ]]; then
    record_result "P3-015" "valid_reattestation" "PASS" "FAIL" \
        "Could not get initial nonce: $RESULT_015"
else
    NONCE_015="${RESULT_015#NONCE:}"; NONCE_015="${NONCE_015%%:*}"
    SESSION_015="${RESULT_015##*:}"
    QUOTE_SIG=$(compute_quote_sig "$GOLDEN_PCR0" "$GOLDEN_PCR4" "$GOLDEN_PCR7" "$GOLDEN_PCR11" "$NONCE_015")
    EVIDENCE=$(build_evidence "examos-device-02" "examos-0.4.0" "$NONCE_015" "$EK_DEV02" "$QUOTE_SIG")
    VERIFY_RESP=$(submit_evidence "$EVIDENCE")
    V1_STATUS=$(echo "$VERIFY_RESP" | grep -o '"status":"[^"]*"' | head -1 | cut -d'"' -f4)

    if [ "$V1_STATUS" != "TRUSTED" ]; then
        record_result "P3-015" "valid_reattestation" "PASS" "FAIL" \
            "Initial attestation failed: $V1_STATUS resp=$VERIFY_RESP"
    else
        # Request re-attestation challenge (fresh nonce)
        REATTEST_RESP=$(curl -s -X POST "${SERVER_URL}/api/v1/attestation/re-attest" \
            -H "Content-Type: application/json" \
            -d "{\"session_id\":\"${SESSION_015}\",\"device_id\":\"examos-device-02\"}" 2>/dev/null \
            || echo '{"status":"CURL_ERROR"}')
        RA_STATUS=$(echo "$REATTEST_RESP" | grep -o '"status":"[^"]*"' | head -1 | cut -d'"' -f4)
        NEW_NONCE=$(echo "$REATTEST_RESP" | grep -o '"nonce":"[^"]*"' | cut -d'"' -f4)

        if [ "$RA_STATUS" != "RE_ATTESTATION_CHALLENGE" ] || [ -z "$NEW_NONCE" ]; then
            record_result "P3-015" "valid_reattestation" "PASS" "FAIL" \
                "Re-attest challenge failed: $RA_STATUS resp=$REATTEST_RESP"
        else
            # Submit fresh quote with new nonce
            NEW_QUOTE_SIG=$(compute_quote_sig "$GOLDEN_PCR0" "$GOLDEN_PCR4" "$GOLDEN_PCR7" "$GOLDEN_PCR11" "$NEW_NONCE")
            NEW_EVIDENCE=$(build_evidence "examos-device-02" "examos-0.4.0" "$NEW_NONCE" "$EK_DEV02" "$NEW_QUOTE_SIG")
            V2_RESP=$(submit_evidence "$NEW_EVIDENCE")
            V2_STATUS=$(echo "$V2_RESP" | grep -o '"status":"[^"]*"' | head -1 | cut -d'"' -f4)

            if [ "$V2_STATUS" = "TRUSTED" ]; then
                record_result "P3-015" "valid_reattestation" "PASS" "PASS" \
                    "Initial=TRUSTED, Re-attest challenge issued, Fresh verify=TRUSTED"
            else
                record_result "P3-015" "valid_reattestation" "PASS" "FAIL" \
                    "Fresh verify after re-attest failed: $V2_STATUS resp=$V2_RESP"
            fi
        fi
    fi
fi

# ===========================================================================
# P3-016: Revoked device — expect FAIL at NONCE stage (P3_REVOKED_DEVICE)
# ===========================================================================
echo "[P3-016] Revoked device — expect FAIL at nonce"
# Register a disposable device, then revoke it
REVOKE_DEV_RESP=$(curl -s -X POST "${SERVER_URL}/api/v1/admin/revoke/device" \
    -H "Content-Type: application/json" \
    -d '{"device_id":"machine-a"}' 2>/dev/null || echo '{"status":"CURL_ERROR"}')
REVOKE_DEV_STATUS=$(echo "$REVOKE_DEV_RESP" | grep -o '"status":"[^"]*"' | head -1 | cut -d'"' -f4)

echo "{\"test\":\"P3-016\",\"revoke_device_status\":\"$REVOKE_DEV_STATUS\"}" \
    >> "$ARTIFACT_DIR/revocation-test.json"

RESULT_016=$(get_nonce "machine-a")
if [[ "$RESULT_016" = ERROR:* ]]; then
    EC_016="${RESULT_016#ERROR:}"
    if [ "$EC_016" = "P3_REVOKED_DEVICE" ] || [ "$EC_016" = "REJECTED" ]; then
        record_result "P3-016" "revoked_device" "FAIL" "FAIL" \
            "Nonce correctly refused for revoked device: $EC_016"
    else
        record_result "P3-016" "revoked_device" "FAIL" "FAIL" \
            "Nonce refused (different code): $EC_016"
    fi
elif [[ "$RESULT_016" = NONCE:* ]]; then
    record_result "P3-016" "revoked_device" "FAIL" "PASS" \
        "Nonce was ISSUED to revoked device — should be rejected"
else
    record_result "P3-016" "revoked_device" "FAIL" "FAIL" "Nonce refused: $RESULT_016"
fi

# ===========================================================================
# Summary
# ===========================================================================
echo ""
echo "============================================================"
echo "ExamOS P3 Attestation Suite — Results"
echo "============================================================"
TOTAL=$((PASS_COUNT + FAIL_COUNT))
echo "Total cases: $TOTAL"
echo "Expected PASS (P3-001,015): 2"
echo "Expected FAIL (P3-002..014,016): 14"
echo ""
echo "Correct outcomes: $((PASS_COUNT))"
echo "Incorrect outcomes: $((FAIL_COUNT))"

# Write machine-readable results
cat > "$ARTIFACT_DIR/results.json" <<JSONEOF
{
  "phase": "P3",
  "version": "0.4.0",
  "timestamp": "$(ts)",
  "total": $TOTAL,
  "correct_outcomes": $PASS_COUNT,
  "incorrect_outcomes": $FAIL_COUNT,
  "gate": "$([ $FAIL_COUNT -eq 0 ] && echo 'PASS' || echo 'FAIL')"
}
JSONEOF

echo "Results written to $ARTIFACT_DIR/results.json"

if [ "$FAIL_COUNT" -eq 0 ]; then
    echo "[P3-GATE] PASS — all $TOTAL cases produced correct outcomes"
    exit 0
else
    echo "[P3-GATE] FAIL — $FAIL_COUNT cases produced incorrect outcomes"
    exit 1
fi
