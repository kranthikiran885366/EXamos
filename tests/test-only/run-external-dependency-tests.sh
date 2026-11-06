#!/usr/bin/env bash
# =============================================================================
# ExamOS test-only external-dependency suite
#
# This suite exercises software substitutes for controls that normally require
# physical hardware, external signing infrastructure, public model artefacts,
# or an LLM service.  Its output is explicitly non-production evidence.
#
# It never sets HARDWARE_TEST=1 unless --physical is supplied.  It never
# enrolls, clears, provisions, or changes a physical TPM.
# =============================================================================
set -uo pipefail

WORKSPACE="$(cd "$(dirname "$0")/../.." && pwd)"
MODE="simulate"
if [ "${1:-}" = "--physical" ]; then
    MODE="physical"
    shift
elif [ "${1:-}" = "--simulate" ] || [ -z "${1:-}" ]; then
    [ "${1:-}" = "--simulate" ] && shift
else
    echo "Usage: $0 [--simulate|--physical]" >&2
    exit 2
fi
[ "$#" -eq 0 ] || { echo "Usage: $0 [--simulate|--physical]" >&2; exit 2; }

if [ -n "${EXAMOS_TEST_ONLY_ARTIFACT_DIR:-}" ]; then
    RUN_DIR="$EXAMOS_TEST_ONLY_ARTIFACT_DIR"
    mkdir -p "$RUN_DIR"
else
    mkdir -p "$WORKSPACE/artifacts/test-only/runs"
    RUN_DIR="$(mktemp -d "$WORKSPACE/artifacts/test-only/runs/run-$(date -u +%Y%m%dT%H%M%SZ)-XXXXXX")"
fi

RESULTS_TSV="$RUN_DIR/checks.tsv"
RESULT_JSON="$RUN_DIR/test-only-external-results.json"
TEST_DATABASE_URL="${EXAMOS_TEST_DATABASE_URL:-${EXAMOS_DATABASE_URL:-}}"
: > "$RESULTS_TSV"
PASS=0
FAIL=0
BLOCKED=0
MANUAL=0

record() {
    local id="$1" status="$2" detail="$3"
    printf '%s\t%s\t%s\n' "$id" "$status" "$detail" >> "$RESULTS_TSV"
    printf '[TEST-ONLY] %-24s %-16s %s\n' "$id" "$status" "$detail"
    case "$status" in
        SIMULATED_PASS|PHYSICAL_PASS) PASS=$((PASS + 1)) ;;
        FAIL) FAIL=$((FAIL + 1)) ;;
        BLOCKED) BLOCKED=$((BLOCKED + 1)) ;;
        MANUAL_REQUIRED) MANUAL=$((MANUAL + 1)) ;;
    esac
}

have_tools() {
    local tool
    for tool in "$@"; do command -v "$tool" >/dev/null 2>&1 || return 1; done
}

run_check() {
    local id="$1" kind="$2"
    shift 2
    local log="$RUN_DIR/${id}.log"
    local rc=0
    "$@" >"$log" 2>&1 || rc=$?
    case "$rc" in
        0) record "$id" "$kind" "completed; log=$log" ;;
        2) record "$id" BLOCKED "prerequisite unavailable; log=$log" ;;
        *) record "$id" FAIL "command exited $rc; log=$log" ;;
    esac
}

run_if_tools() {
    local id="$1" kind="$2" tools="$3"
    shift 3
    local tool
    local missing=""
    for tool in $tools; do
        command -v "$tool" >/dev/null 2>&1 || missing="${missing}${missing:+, }${tool}"
    done
    if [ -n "$missing" ]; then
        record "$id" BLOCKED "missing tool(s): $missing"
    else
        run_check "$id" "$kind" "$@"
    fi
}

run_physical_usb_check() {
    local evidence_dir="$RUN_DIR/physical-usb"
    local log="$RUN_DIR/physical_usb_observation.log"
    local rc=0 status=""
    if ! have_tools bash journalctl systemctl; then
        record physical_usb_observation BLOCKED "required host tools are unavailable"
        return
    fi
    env HARDWARE_TEST=1 ARTIFACT_DIR="$evidence_dir" \
        bash "$WORKSPACE/tests/p2/p2-usb-tests.sh" >"$log" 2>&1 || rc=$?
    if [ -s "$evidence_dir/usb-policy-tests.json" ]; then
        status=$(python3 - "$evidence_dir/usb-policy-tests.json" <<'PY'
import json
import sys
try:
    print(json.load(open(sys.argv[1], encoding="utf-8")).get("overall", "INVALID"))
except (OSError, ValueError):
    print("INVALID")
PY
)
    fi
    case "$status" in
        PASS) record physical_usb_observation PHYSICAL_PASS "physical USB enforcement observed; log=$log" ;;
        BLOCKED) record physical_usb_observation BLOCKED "physical USB evidence unavailable; log=$log" ;;
        FAIL) record physical_usb_observation FAIL "physical USB policy failure; log=$log" ;;
        *) record physical_usb_observation FAIL "invalid USB test evidence (exit=$rc); log=$log" ;;
    esac
}

database_backed_checks_available() {
    if [ -z "$TEST_DATABASE_URL" ]; then
        return 1
    fi
    command -v psql >/dev/null 2>&1 || return 1
    psql "$TEST_DATABASE_URL" -v ON_ERROR_STOP=1 -qtAc 'SELECT 1' \
        >"$RUN_DIR/test-database-probe.log" 2>&1
}

echo "=== ExamOS external-dependency test suite ==="
echo "Mode: $MODE"
echo "Evidence: $RUN_DIR"
echo "This evidence is TEST ONLY and is rejected by production gates."

# PG-13: Deterministic policy fixtures, not a physical device observation.
run_check usb_policy_simulation SIMULATED_PASS \
    python3 "$WORKSPACE/tests/test-only/usb-policy-simulator.py" \
    --rules "$WORKSPACE/image/overlay/etc/usbguard/rules.conf" \
    --daemon-conf "$WORKSPACE/image/overlay/etc/usbguard/usbguard-daemon.conf" \
    --udev-rule "$WORKSPACE/image/overlay/etc/udev/rules.d/99-examos-usb-lockdown.rules" \
    --output "$RUN_DIR/usb-policy-simulation.json"

# PG-12: Cryptographic hash-tree formatting and corruption rejection on
# temporary regular files; this is not proof that the production root boots
# through dm-verity.
run_if_tools dm_verity_roundtrip SIMULATED_PASS "veritysetup sha256sum dd" \
    bash "$WORKSPACE/tests/test-only/dm-verity-roundtrip.sh"

# PG-14: This checks policy/profile source. The live Chromium + AppArmor
# portion remains a guest-only physical/runtime check.
run_if_tools chromium_policy_source SIMULATED_PASS "bash python3" \
    env ARTIFACT_DIR="$RUN_DIR/chromium-policy" \
    bash "$WORKSPACE/tests/p2/p2-chromium-policy-tests.sh"

# PG-18 through PG-21: disposable keys and a software TPM exercise the real
# protocol code without masquerading as an EK chain or physical TPM result.
run_if_tools signed_registry_simulation SIMULATED_PASS "cc openssl python3" \
    bash "$WORKSPACE/tests/p3/production-registry.sh"
run_if_tools swtpm_quote_simulation SIMULATED_PASS \
    "swtpm tpm2_startup tpm2_createprimary tpm2_createak tpm2_createek tpm2_readpublic tpm2_flushcontext tpm2_quote tpm2_pcrread tpm2_checkquote openssl xxd python3 cc" \
    bash "$WORKSPACE/tests/p3/swtpm-quote-smoke.sh"
run_if_tools credential_activation_simulation SIMULATED_PASS \
    "swtpm tpm2_startup tpm2_createek tpm2_createak tpm2_readpublic tpm2_makecredential tpm2_startauthsession tpm2_policysecret tpm2_activatecredential tpm2_flushcontext openssl xxd python3" \
    bash "$WORKSPACE/tests/p3/credential-activation-smoke.sh"
run_if_tools event_log_replay_simulation SIMULATED_PASS "python3" \
    python3 "$WORKSPACE/tests/p3/test-eventlog-replay.py"
# PG-23 through PG-25: Create the labelled synthetic fixture outside the
# source tree. It validates ingestion fixtures only, never model accuracy.
run_if_tools synthetic_video_fixture SIMULATED_PASS "ffmpeg python3" \
    env EXAMOS_P4_TEST_DATASET_DIR="$RUN_DIR/p4-synthetic-dataset" \
    bash "$WORKSPACE/tests/p4/generate-test-dataset.sh"

# The following tests use a live server and therefore need a disposable,
# reachable PostgreSQL database. Do not silently fall back to a developer's
# default database or report the missing database as a product defect.
if database_backed_checks_available; then
    run_if_tools tpm_attestation_e2e_simulation SIMULATED_PASS \
        "swtpm tpm2_startup tpm2_createek tpm2_createak tpm2_readpublic tpm2_quote openssl xxd curl" \
        env EXAMOS_DATABASE_URL="$TEST_DATABASE_URL" \
        bash "$WORKSPACE/tests/server/test_module_h_attestation_e2e.sh"
    run_if_tools p4_tamper_matrix SIMULATED_PASS "bash gcc curl openssl python3" \
        env EXAMOS_DATABASE_URL="$TEST_DATABASE_URL" EXAMOS_P4_ARTIFACT_DIR="$RUN_DIR/p4-tamper" \
        bash "$WORKSPACE/tests/p4/p4-tamper-test.sh"
    run_if_tools p4_concurrency SIMULATED_PASS "bash curl openssl python3" \
        env EXAMOS_DATABASE_URL="$TEST_DATABASE_URL" EXAMOS_P4_ARTIFACT_DIR="$RUN_DIR/p4-concurrency" \
        bash "$WORKSPACE/tests/p4/p4-concurrency-test.sh"
else
    record tpm_attestation_e2e_simulation BLOCKED "set EXAMOS_TEST_DATABASE_URL to a disposable reachable PostgreSQL database"
    record p4_tamper_matrix BLOCKED "set EXAMOS_TEST_DATABASE_URL to run the server-backed tamper matrix"
    record p4_concurrency BLOCKED "set EXAMOS_TEST_DATABASE_URL to run the server-backed 50-session test"
fi

# PG-29: the deterministic fallback is exercised directly without an LLM
# endpoint or API key. The result must identify itself as OFFLINE_FALLBACK.
run_if_tools viva_offline_fallback SIMULATED_PASS "cc openssl" \
    bash "$WORKSPACE/tests/test-only/viva-offline-fallback-test.sh"

# These matters have no faithful software substitute. They are kept visible
# so a green simulated suite cannot be mistaken for a release decision.
record architecture_hardware_matrix MANUAL_REQUIRED "requires declared hardware models and real-device qualification"
record red_team_assessment MANUAL_REQUIRED "requires an independent security exercise"
record key_custody_ceremony MANUAL_REQUIRED "requires organization-controlled production keys/HSM custody"
record pilot_acceptance MANUAL_REQUIRED "requires supervised operational pilot and sign-off"

if [ "$MODE" = "physical" ]; then
    # These commands only observe the current device or policy state. They do
    # not enroll/clear a TPM and do not modify firmware.
    run_physical_usb_check
    run_if_tools physical_tpm_preflight PHYSICAL_PASS \
        "bash tpm2_getcap tpm2_pcrread tpm2_readpublic tpm2_quote tpm2_checkquote" \
        env EXAMOS_P3_ARTIFACT_DIR="$RUN_DIR/physical-tpm" \
        bash "$WORKSPACE/tests/p3/hardware-tpm-preflight.sh"
    run_if_tools physical_trust_gate PHYSICAL_PASS \
        "bash tpm2_getcap tpm2_pcrread tpm2_readpublic tpm2_quote tpm2_checkquote tpm2_eventlog openssl xxd python3 curl" \
        env EXAMOS_PRODUCTION_ARTIFACT_DIR="$RUN_DIR/physical-trust" \
        bash "$WORKSPACE/tests/production/hardware-trust-gate.sh"
    record live_chromium_apparmor MANUAL_REQUIRED "boot the rebuilt guest, start Chromium, then run tests/p2/p2-guest-integration.sh inside it"
else
    record physical_usb_observation MANUAL_REQUIRED "rerun with --physical and a USB mass-storage device to observe enforcement"
    record physical_tpm_preflight MANUAL_REQUIRED "rerun with --physical on Linux with /dev/tpmrm0 or /dev/tpm0"
    record live_chromium_apparmor MANUAL_REQUIRED "requires a booted guest with Cage and Chromium running"
fi

export EXAMOS_TEST_ONLY_MODE="$MODE"
export EXAMOS_TEST_ONLY_PASS="$PASS"
export EXAMOS_TEST_ONLY_FAIL="$FAIL"
export EXAMOS_TEST_ONLY_BLOCKED="$BLOCKED"
export EXAMOS_TEST_ONLY_MANUAL="$MANUAL"
python3 - "$RESULTS_TSV" "$RESULT_JSON" <<'PY'
import datetime
import json
import os
import pathlib
import sys

checks = []
for line in pathlib.Path(sys.argv[1]).read_text(encoding="utf-8").splitlines():
    check_id, status, detail = line.split("\t", 2)
    checks.append({"id": check_id, "status": status, "detail": detail})
failed = int(os.environ["EXAMOS_TEST_ONLY_FAIL"])
blocked = int(os.environ["EXAMOS_TEST_ONLY_BLOCKED"])
overall = "TEST_ONLY_FAIL" if failed else "TEST_ONLY_INCOMPLETE" if blocked else "TEST_ONLY_PASS"
report = {
    "schema": "examos.test-only.external-dependencies.v1",
    "generated_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "mode": os.environ["EXAMOS_TEST_ONLY_MODE"],
    "test_only": True,
    "production_evidence": False,
    "overall": overall,
    "summary": {
        "passed": int(os.environ["EXAMOS_TEST_ONLY_PASS"]),
        "failed": failed,
        "blocked": blocked,
        "manual_required": int(os.environ["EXAMOS_TEST_ONLY_MANUAL"]),
    },
    "checks": checks,
    "release_note": "No SIMULATED_PASS or TEST_ONLY_PASS result satisfies a production, physical-hardware, PKI, model-quality, red-team, or pilot gate.",
}
pathlib.Path(sys.argv[2]).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
print(json.dumps(report, indent=2))
PY

echo "[TEST-ONLY] Result: $RESULT_JSON"
[ "$FAIL" -eq 0 ] || exit 1
[ "$BLOCKED" -eq 0 ] || exit 2
exit 0
