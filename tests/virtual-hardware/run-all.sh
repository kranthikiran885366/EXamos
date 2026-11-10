#!/usr/bin/env bash
set -euo pipefail
umask 077

WORKSPACE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VH_DIR="$WORKSPACE/tests/virtual-hardware"
EVIDENCE_ROOT="$VH_DIR/evidence"
REPORT_TOOL="$VH_DIR/scripts/reports.py"
mkdir -p -- "$EVIDENCE_ROOT"

if [[ -n "${EXAMOS_VH_RUN_DIR:-}" ]]; then
    RUN_DIR="$(realpath -m -- "$EXAMOS_VH_RUN_DIR")"
    case "$RUN_DIR" in
        "$EVIDENCE_ROOT"/*) ;;
        *)
            echo "[VH-RUN] FAIL: EXAMOS_VH_RUN_DIR must be inside $EVIDENCE_ROOT." >&2
            exit 1
            ;;
    esac
else
    RUN_ID="${EXAMOS_VH_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)-$$-$RANDOM}"
    [[ "$RUN_ID" =~ ^[A-Za-z0-9._-]+$ ]] || {
        echo "[VH-RUN] FAIL: EXAMOS_VH_RUN_ID contains unsupported characters." >&2
        exit 1
    }
    RUN_DIR="$EVIDENCE_ROOT/$RUN_ID"
fi
[[ ! -e "$RUN_DIR" && ! -L "$RUN_DIR" ]] || {
    echo "[VH-RUN] FAIL: refusing to reuse or overwrite run directory: $RUN_DIR" >&2
    exit 1
}
mkdir -m 700 -- "$RUN_DIR"
mkdir -m 700 -- "$RUN_DIR/logs" "$RUN_DIR/reports"
export EXAMOS_VH_RUN_DIR="$RUN_DIR"

SOURCE_COMMIT="$(git -C "$WORKSPACE" rev-parse HEAD 2>/dev/null || printf unknown)"
LAST_STATUS="NOT TESTED"

run_step() {
    local test_id="$1" name="$2" objective="$3" preconditions="$4"
    local expected="$5" evidence="$6"
    shift 6
    local log="$RUN_DIR/logs/$test_id.log"
    local rc status command_text details
    command_text="$(printf '%q ' "$@")"
    if "$@" > "$log" 2>&1; then
        rc=0
        status="PASS"
        details="Command completed successfully; see the run log."
    else
        rc=$?
        if [[ "$rc" -eq 2 ]]; then
            status="BLOCKED"
            details="Command reported a missing prerequisite; see the run log."
        else
            status="FAIL"
            details="Command exited with status $rc; see the run log."
        fi
    fi
    LAST_STATUS="$status"
    python3 "$REPORT_TOOL" record \
        --run-dir "$RUN_DIR" --test-id "$test_id" --name "$name" \
        --objective "$objective" --preconditions "$preconditions" \
        --command "$command_text" --expected "$expected" \
        --actual "$details" --status "$status" \
        --evidence "$evidence" --log "${log#"$RUN_DIR"/}" \
        --details "$details" --source-commit "$SOURCE_COMMIT"
    printf '[VH-RUN] %s: %s (exit %s)\n' "$test_id" "$status" "$rc"
}

run_blocked() {
    local test_id="$1" name="$2" objective="$3" preconditions="$4"
    local expected="$5" evidence="$6" details="$7"
    local log="$RUN_DIR/logs/$test_id.log"
    printf '%s\n' "$details" > "$log"
    python3 "$REPORT_TOOL" record \
        --run-dir "$RUN_DIR" --test-id "$test_id" --name "$name" \
        --objective "$objective" --preconditions "$preconditions" \
        --command "not executed" --expected "$expected" \
        --actual "$details" --status "BLOCKED" \
        --evidence "$evidence" --log "${log#"$RUN_DIR"/}" \
        --details "$details" --source-commit "$SOURCE_COMMIT"
    printf '[VH-RUN] %s: BLOCKED\n' "$test_id"
}

run_step TOOLCHAIN_PREFLIGHT "Host and toolchain preflight" \
    "Inventory source artifacts, virtualization, and required host tools." \
    "WSL or Linux; Python 3; no elevated privileges." \
    "Record detected capabilities without changing the host." \
    "reports/toolchain-inventory.json" \
    bash "$VH_DIR/scripts/preflight.sh"

if [[ "$LAST_STATUS" == "PASS" ]]; then
    run_step VM_CREATE "Create isolated VM state" \
        "Create a qcow2 overlay, private OVMF variables, and separate swtpm state." \
        "QEMU, qemu-img, OVMF, and swtpm are installed." \
        "Original raw image remains unchanged; networking and monitor are disabled." \
        "epoch-*/vm.json" \
        bash "$VH_DIR/scripts/create-vm.sh"
else
    run_blocked VM_CREATE "Create isolated VM state" \
        "Create a qcow2 overlay, private OVMF variables, and separate swtpm state." \
        "Required host preflight passes." \
        "VM state is created without modifying the source image." \
        "epoch-*/vm.json" "Host preflight did not pass."
fi

run_step QEMU_BOOT "UEFI boot with virtual TPM" \
    "Boot the selected raw image using a disposable overlay and swtpm; verify kiosk readiness and quote post-boot PCRs." \
    "VM state, OVMF, QEMU, and swtpm are available." \
    "Guest reports Cage, Wayland socket, and Chromium readiness; tpm2_checkquote verifies fresh virtual evidence." \
    "epoch-*/serial.log and qemu-boot/" \
    bash "$VH_DIR/tests/qemu-boot.sh"

run_step UKI_ARTIFACT "Build and verify a test-signed UKI" \
    "Build from existing kernel/initrd and test signed, unsigned, modified, and untrusted-key artifacts." \
    "ukify, sbsign, sbverify, OpenSSL, kernel, and initrd are available." \
    "Artifact signatures are verified; no firmware enforcement claim is inferred." \
    "uki/" \
    bash "$VH_DIR/tests/uki-validation.sh"

run_step SWTPM_QUOTE "Virtual TPM quote and tamper tests" \
    "Create a fresh virtual TPM quote and validate its AK, nonce, PCR selection, signature, and negative cases." \
    "swtpm, tpm2-tools, OpenSSL, and C compiler are available." \
    "Valid quote passes; incorrect nonce/PCR values and modified signature are rejected." \
    "tpm-quote/" \
    bash "$VH_DIR/tests/tpm-quote.sh"

run_step DM_VERITY_ARTIFACT "dm-verity data and tree tests" \
    "Verify disposable data and reject single/multiple block, hash-tree, and root-hash tampering." \
    "veritysetup and Python 3 are available." \
    "All integrity mutations are explicitly rejected." \
    "dm-verity/" \
    bash "$VH_DIR/tests/dm-verity.sh"

run_step POSTGRES_INTEGRATION "Disposable PostgreSQL integration" \
    "Apply all migrations, verify idempotency/rollback, exercise auth create/update/read, restart persistence, and attestation DB transitions." \
    "Non-root WSL/Linux user; local PostgreSQL server tools; TLS/OpenSSL; compiler." \
    "Every DB operation targets a new local loopback-only cluster and is removed after evidence is saved." \
    "postgres/" \
    bash "$VH_DIR/tests/postgres-integration.sh"

CEREMONY_PARENT="$(mktemp -d "${TMPDIR:-/tmp}/sppio-vh-ceremony.XXXXXX")"
CEREMONY_TMP="$CEREMONY_PARENT/work"
run_step PHYSICAL_CEREMONY_SWTPM "Offline TPM ceremony software test" \
    "Exercise request validation, MakeCredential/ActivateCredential, TPM public-area binding, quote verification, tampering rejection, and unsigned candidate generation using swtpm." \
    "Python 3, OpenSSL, tpm2-tools, and swtpm are available." \
    "Only the test fixture passes; no candidate is production-signed or automatically enrolled." \
    "ceremony test log" \
    env EXAMOS_TPM_TEST_WORKDIR="$CEREMONY_TMP" \
    python3 "$WORKSPACE/tests/p3/physical-tpm-ceremony.py"
rm -rf -- "$CEREMONY_PARENT"

run_step SIGNED_REGISTRY_TEST "Signed registry security regression" \
    "Check production registry signatures, external key pins, institution binding, and fail-closed rejection using ephemeral test keys." \
    "C compiler, Python 3, and OpenSSL are available." \
    "All valid test entries are accepted and invalid/test-tampered cases are rejected." \
    "signed registry test log" \
    bash "$WORKSPACE/tests/p3/production-registry.sh"

run_step CREDENTIAL_AUDIT "Credential-free image audit" \
    "Verify release configuration contains only unprovisioned secret placeholders." \
    "Python 3 and repository files are available." \
    "Audit has no findings; no secret values are printed." \
    "credential audit log" \
    python3 "$WORKSPACE/tests/p3/release-gate.py" --credential-audit

run_step KIOSK_SANDBOX_REGRESSION "Kiosk sandbox configuration regression" \
    "Verify the kiosk unit, AppArmor profile, userns sysctl, readiness stability, and boot gate stay consistent." \
    "Repository kiosk configuration files are available." \
    "The sandbox prerequisites required by the QEMU kiosk gate are present and no invalid AppArmor rule is reintroduced." \
    "Kiosk sandbox regression log" \
    bash "$WORKSPACE/tests/p3/kiosk-sandbox-regression.sh"

run_step SCRIPT_SYNTAX "Shell and Python syntax validation" \
    "Parse all virtual-hardware scripts and Python utilities without installing linters." \
    "Bash and Python 3 are available; ShellCheck absence is reported separately." \
    "No syntax errors are found." \
    "syntax validation log" \
    bash "$VH_DIR/scripts/syntax-check.sh" "$WORKSPACE"

python3 "$REPORT_TOOL" finalize --run-dir "$RUN_DIR" \
    > "$RUN_DIR/logs/report-generation.log" 2>&1
decision="$(python3 - "$RUN_DIR/reports/phase3-summary.json" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as stream:
    print(json.load(stream)["overall_decision"])
PY
)"
python3 "$REPORT_TOOL" manifest --run-dir "$RUN_DIR" >/dev/null
printf '[VH-RUN] %s\n' "$decision"
printf '[VH-RUN] Reports: %s/reports\n' "$RUN_DIR"
printf '[VH-RUN] Evidence manifest: %s/evidence-sha256.txt\n' "$RUN_DIR"

case "$decision" in
    "SOFTWARE VALIDATION FAILED"*) exit 1 ;;
    "SOFTWARE VALIDATION BLOCKED"*) exit 2 ;;
    "SOFTWARE VALIDATION PARTIALLY PASSED"*) exit 2 ;;
    *) exit 0 ;;
esac
