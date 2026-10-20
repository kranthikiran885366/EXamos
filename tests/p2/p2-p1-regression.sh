#!/usr/bin/env bash
# =============================================================================
# ExamOS P2 — P1 Regression Tests (Layer 6)
# Mandatory: P2-18
#
# Re-runs the P1 static checks and a subset of the P1 boot verification to
# ensure Phase 2 lockdown changes have not broken the Phase 1 kiosk contract.
# =============================================================================
set -uo pipefail

WORKSPACE=$(cd "$(dirname "$0")/../.." && pwd)
ARTIFACT_DIR="${ARTIFACT_DIR:-$WORKSPACE/artifacts/phase2}"
P1_ARTIFACT_DIR="${P1_ARTIFACT_DIR:-$ARTIFACT_DIR/p1-boot}"
mkdir -p "$ARTIFACT_DIR"
mkdir -p "$P1_ARTIFACT_DIR"

LOG="$ARTIFACT_DIR/p1-regression-results.log"
exec > >(tee "$LOG") 2>&1

PASS=0; FAIL=0; BLOCKED=0
ts() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

record() {
    local id="$1" status="$2" detail="$3"
    case "$status" in
        PASS)    PASS=$((PASS+1));    echo "[P1-REG-PASS]    ${id}: ${detail}" ;;
        FAIL)    FAIL=$((FAIL+1));    echo "[P1-REG-FAIL]    ${id}: ${detail}" >&2 ;;
        BLOCKED) BLOCKED=$((BLOCKED+1)); echo "[P1-REG-BLOCKED] ${id}: ${detail}" ;;
    esac
}
overall_status() {
    if [ "$FAIL" -gt 0 ]; then echo "FAIL"
    elif [ "$BLOCKED" -gt 0 ]; then echo "BLOCKED"
    elif [ "$PASS" -gt 0 ]; then echo "PASS"
    else echo "NOT_RUN"
    fi
}

echo "=== [P2-P1-REGRESSION] P1 Regression: $(ts) ==="

# ---------------------------------------------------------------------------
# Run the actual P1 static verification scripts
# ---------------------------------------------------------------------------
echo "--- Re-running P1 kiosk static check ---"
if bash "$WORKSPACE/tests/p1/kiosk.sh" >/dev/null 2>&1; then
    record "P1-REG-KIOSK" "PASS" "P1 kiosk.sh static check passed"
else
    record "P1-REG-KIOSK" "FAIL" "P1 kiosk.sh static check FAILED"
fi

echo "--- Re-running P1 network static check ---"
if bash "$WORKSPACE/tests/p1/network.sh" >/dev/null 2>&1; then
    record "P1-REG-NETWORK" "PASS" "P1 network.sh static check passed"
else
    record "P1-REG-NETWORK" "FAIL" "P1 network.sh static check FAILED"
fi

# ---------------------------------------------------------------------------
# Verify P1 invariants still hold in modified files
# ---------------------------------------------------------------------------
KIOSK_SVC="$WORKSPACE/image/overlay/etc/systemd/system/examos-kiosk.service"

# P1: kiosk must still run as exam user
if grep -q "^User=exam$" "$KIOSK_SVC" 2>/dev/null; then
    record "P1-REG-USER" "PASS" "examos-kiosk.service User=exam preserved"
else
    record "P1-REG-USER" "FAIL" "examos-kiosk.service User=exam MISSING — P1 regression"
fi

# P1: cage still referenced
if grep -q "cage" "$KIOSK_SVC" 2>/dev/null; then
    record "P1-REG-CAGE" "PASS" "cage compositor reference preserved"
else
    record "P1-REG-CAGE" "FAIL" "cage reference missing from kiosk service — P1 regression"
fi

# P1: WantedBy graphical.target preserved
if grep -q "WantedBy=graphical.target" "$KIOSK_SVC" 2>/dev/null; then
    record "P1-REG-TARGET" "PASS" "WantedBy=graphical.target preserved"
else
    record "P1-REG-TARGET" "FAIL" "WantedBy=graphical.target missing — P1 regression"
fi

# P1: Restart=on-failure (not always — prevents infinite loop on deliberate stop)
if grep -q "^Restart=on-failure$" "$KIOSK_SVC" 2>/dev/null; then
    record "P1-REG-RESTART" "PASS" "Restart=on-failure preserved"
else
    record "P1-REG-RESTART" "FAIL" "Restart policy changed — P1 regression"
fi

# P1: no --no-sandbox in launcher
LAUNCHER="$WORKSPACE/kiosk/launcher/launcher.c"
if [ -f "$LAUNCHER" ]; then
    if grep -q "\-\-no-sandbox" "$LAUNCHER"; then
        record "P1-REG-SANDBOX" "FAIL" "--no-sandbox found in launcher.c — P1+P2 regression"
    else
        record "P1-REG-SANDBOX" "PASS" "launcher.c: no --no-sandbox flag"
    fi
    if grep -q "\-\-disable-gpu-sandbox" "$LAUNCHER"; then
        record "P1-REG-GPUSB" "FAIL" "--disable-gpu-sandbox found in launcher.c"
    else
        record "P1-REG-GPUSB" "PASS" "launcher.c: no --disable-gpu-sandbox"
    fi
fi

# P1: exam user still in sysusers
SYSUSERS="$WORKSPACE/image/overlay/usr/lib/sysusers.d/examos.conf"
if [ -f "$SYSUSERS" ] && grep -q "^u exam 1000" "$SYSUSERS"; then
    record "P1-REG-SYSUSERS" "PASS" "exam UID=1000 nologin in sysusers.d"
else
    record "P1-REG-SYSUSERS" "FAIL" "exam user missing from sysusers.d — P1 regression"
fi

# P1: no desktop environment added
for de in gnome kde xfce lightdm gdm3 lxde; do
    if grep -qiE "^\s+${de}(\s|$)" "$WORKSPACE/image/mkosi.conf" 2>/dev/null; then
        record "P1-REG-DE-${de}" "FAIL" "Desktop environment '${de}' added to mkosi.conf — P1 regression"
    else
        record "P1-REG-DE-${de}" "PASS" "No '${de}' DE in mkosi.conf"
    fi
done

# P1: graphical.target.wants symlink exists (after build script creates it)
# In the source tree we verify the build script creates it
if grep -q "graphical.target.wants.*examos-kiosk.service" "$WORKSPACE/image/scripts/03-p2-lockdown.sh" 2>/dev/null; then
    record "P1-REG-WANTS" "PASS" "graphical.target.wants/examos-kiosk.service created in build script"
else
    KIOSK_LINK="$WORKSPACE/image/overlay/etc/systemd/system/graphical.target.wants/examos-kiosk.service"
    KIOSK_LINK_TARGET=$(readlink "$KIOSK_LINK" 2>/dev/null || true)
    if [ "$KIOSK_LINK_TARGET" = "/etc/systemd/system/examos-kiosk.service" ] || \
       [ "$KIOSK_LINK_TARGET" = "../examos-kiosk.service" ]; then
        record "P1-REG-WANTS" "PASS" "graphical.target.wants/examos-kiosk.service symlink in overlay"
    else
        record "P1-REG-WANTS" "FAIL" "graphical.target.wants/examos-kiosk.service link target invalid or missing"
    fi
fi

# P1: exam.conf exists
if [ -f "$WORKSPACE/image/overlay/etc/examos/exam.conf" ]; then
    record "P1-REG-EXAMCONF" "PASS" "/etc/examos/exam.conf present"
else
    record "P1-REG-EXAMCONF" "FAIL" "/etc/examos/exam.conf missing — P1 regression"
fi

# ---------------------------------------------------------------------------
# Run P1 boot test (re-uses existing boot.sh which is P2-safe)
# ---------------------------------------------------------------------------
if [ -f "$WORKSPACE/tests/p1/boot.sh" ]; then
    echo "--- Re-running P1 boot test ---"
    mkdir -p "$P1_ARTIFACT_DIR"
    source "$WORKSPACE/scripts/examos-lib.sh"
    IMAGE_FILE=$(examos_find_image "$WORKSPACE") || IMAGE_FILE=""
    if [ -z "$IMAGE_FILE" ]; then
        record "P1-REG-BOOT" "BLOCKED" "No current build image available for P1 boot regression"
    else
        IMAGE_RELATIVE=$(realpath --relative-to="$WORKSPACE" "$IMAGE_FILE")
        case "$IMAGE_RELATIVE" in
            ""|/*|../*|*/../*|*/..)
                record "P1-REG-BOOT" "FAIL" "Built image path is not workspace-relative: ${IMAGE_FILE}"
                IMAGE_RELATIVE=""
                ;;
        esac
        if [ -n "$IMAGE_RELATIVE" ]; then
            (cd "$WORKSPACE" && sha256sum "$IMAGE_RELATIVE") > "$P1_ARTIFACT_DIR/image.sha256"
            P1_BOOT_RC=0
            P1_ARTIFACT_DIR="$P1_ARTIFACT_DIR" timeout 110 bash "$WORKSPACE/tests/p1/boot.sh" \
                > "$ARTIFACT_DIR/p1-regression-boot.log" 2>&1 || P1_BOOT_RC=$?
            if [ "$P1_BOOT_RC" -eq 0 ] && \
               grep -q '"status": "PASS"' "$P1_ARTIFACT_DIR/boot-status.json"; then
                record "P1-REG-BOOT" "PASS" "P1 boot markers confirmed by the live boot test"
            else
                record "P1-REG-BOOT" "FAIL" "P1 boot test failed (rc=${P1_BOOT_RC}); see p1-regression-boot.log"
                tail -20 "$ARTIFACT_DIR/p1-regression-boot.log" >&2 || true
            fi
        fi
    fi
else
    record "P1-REG-BOOT" "BLOCKED" "P1 boot.sh not found"
fi

# ---------------------------------------------------------------------------
# Write results
# ---------------------------------------------------------------------------
{
    printf '{"timestamp":"%s","pass":%d,"fail":%d,"blocked":%d,"overall":"%s"}\n' \
        "$(ts)" "$PASS" "$FAIL" "$BLOCKED" "$(overall_status)"
} > "$ARTIFACT_DIR/p1-regression-results.json"

echo ""
echo "=== [P1-REGRESSION] PASS=${PASS} FAIL=${FAIL} BLOCKED=${BLOCKED} ==="
[ "$FAIL" -eq 0 ]
