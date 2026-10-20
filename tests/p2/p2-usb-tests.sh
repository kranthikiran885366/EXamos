#!/usr/bin/env bash
# =============================================================================
# ExamOS P2 — USB Policy Tests (Layer 7 / Hardware)
# Mandatory: P2-12
#
# Tests run in two modes:
#   1. VM mode  — validates udev rules and USBGuard config without real devices
#   2. Hardware — validates with real USB devices (requires HARDWARE_TEST=1)
#
# NOTE: VM tests validate the POLICY configuration but cannot prove real USB
# hardware behavior. Hardware tests must run in the physical release gate.
# =============================================================================
set -uo pipefail

WORKSPACE="$(cd "$(dirname "$0")/../.." && pwd)"
ARTIFACT_DIR="${ARTIFACT_DIR:-${EXAMOS_P2_ARTIFACT_DIR:-$WORKSPACE/artifacts/phase2}}"
HARDWARE_TEST="${HARDWARE_TEST:-0}"
mkdir -p "$ARTIFACT_DIR"

LOG="$ARTIFACT_DIR/usb-policy-tests.log"
exec > >(tee "$LOG") 2>&1

PASS=0; FAIL=0; BLOCKED=0
ts() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

record() {
    local id="$1" status="$2" detail="$3"
    case "$status" in
        PASS)    PASS=$((PASS+1));    echo "[USB-PASS]    ${id}: ${detail}" ;;
        FAIL)    FAIL=$((FAIL+1));    echo "[USB-FAIL]    ${id}: ${detail}" >&2 ;;
        BLOCKED) BLOCKED=$((BLOCKED+1)); echo "[USB-BLOCKED] ${id}: ${detail}" ;;
    esac
}
overall_status() {
    if [ "$FAIL" -gt 0 ]; then echo "FAIL"
    elif [ "$BLOCKED" -gt 0 ]; then echo "BLOCKED"
    elif [ "$PASS" -gt 0 ]; then echo "PASS"
    else echo "NOT_RUN"
    fi
}

echo "=== [P2-USB] USB Policy Tests: $(ts) ==="

RULES="${USB_RULES_FILE:-/etc/usbguard/rules.conf}"
DAEMON_CONF="${USB_DAEMON_CONF_FILE:-/etc/usbguard/usbguard-daemon.conf}"
UDEV_RULE="${USB_UDEV_RULE_FILE:-/etc/udev/rules.d/99-examos-usb-lockdown.rules}"
if [ ! -f "$RULES" ]; then
    RULES="$WORKSPACE/image/overlay/etc/usbguard/rules.conf"
fi
if [ ! -f "$DAEMON_CONF" ]; then
    DAEMON_CONF="$WORKSPACE/image/overlay/etc/usbguard/usbguard-daemon.conf"
fi
if [ ! -f "$UDEV_RULE" ]; then
    UDEV_RULE="$WORKSPACE/image/overlay/etc/udev/rules.d/99-examos-usb-lockdown.rules"
fi

# ---------------------------------------------------------------------------
# U-01: USB authorized_default=0 on all host controllers
# ---------------------------------------------------------------------------
USB_TOTAL=0; USB_ZERO=0
for ctrl in /sys/bus/usb/devices/usb*; do
    [ -f "$ctrl/authorized_default" ] || continue
    USB_TOTAL=$((USB_TOTAL+1))
    VAL=$(cat "$ctrl/authorized_default" 2>/dev/null || echo "-1")
    echo "[USB] Controller $(basename $ctrl): authorized_default=${VAL}"
    [ "$VAL" = "0" ] && USB_ZERO=$((USB_ZERO+1))
done

if [ "$USB_TOTAL" -eq 0 ]; then
    record "U-01" "BLOCKED" "BLOCKED_ENVIRONMENT: no USB host controllers found in /sys/bus/usb/devices/"
elif [ "$USB_ZERO" -eq "$USB_TOTAL" ]; then
    record "U-01" "PASS" "All ${USB_TOTAL} USB host controllers have authorized_default=0"
else
    record "U-01" "FAIL" "Only ${USB_ZERO}/${USB_TOTAL} controllers have authorized_default=0"
fi

# ---------------------------------------------------------------------------
# U-02: USBGuard daemon running
# ---------------------------------------------------------------------------
if command -v usbguard >/dev/null 2>&1; then
    USBG_STATE=$(systemctl is-active usbguard 2>/dev/null || echo "inactive")
    if [ "$USBG_STATE" = "active" ]; then
        record "U-02" "PASS" "usbguard service is active"
    else
        # USBGuard may not run in VM (no USB devices) — check if it's configured
        if [ -f "$RULES" ]; then
            record "U-02" "BLOCKED" "BLOCKED_ENVIRONMENT: usbguard not active (state=${USBG_STATE}); policy source exists, deployed runtime is unverified"
        else
            record "U-02" "FAIL" "usbguard not active and not configured"
        fi
    fi
else
    record "U-02" "BLOCKED" "BLOCKED_ENVIRONMENT: usbguard binary not available"
fi

# ---------------------------------------------------------------------------
# U-03: USBGuard policy — storage class blocked, HID allowed, composite blocked
# ---------------------------------------------------------------------------
if [ -f "$RULES" ]; then
    # Check block storage rule present
    if grep -q "08:\*:\*" "$RULES"; then
        record "U-03-STORAGE" "PASS" "USBGuard rule blocks USB Mass Storage (class 08)"
    else
        record "U-03-STORAGE" "FAIL" "USBGuard missing storage block rule for class 08"
    fi
    # Check composite HID+storage blocked
    if grep -qP "all-of.*03.*08|all-of.*08.*03" "$RULES"; then
        record "U-03-COMPOSITE" "PASS" "USBGuard blocks composite HID+Storage devices"
    else
        record "U-03-COMPOSITE" "FAIL" "USBGuard missing composite HID+Storage block rule"
    fi
    # Check HID allowed
    if grep -qP "allow.*03:\*:\*" "$RULES"; then
        record "U-03-HID" "PASS" "USBGuard allows HID devices (class 03)"
    else
        record "U-03-HID" "FAIL" "USBGuard missing HID allow rule"
    fi
    # Check ImplicitPolicyTarget=block
    if [ -f "$DAEMON_CONF" ] && grep -q "ImplicitPolicyTarget=block" "$DAEMON_CONF"; then
        record "U-03-IMPLICIT" "PASS" "USBGuard ImplicitPolicyTarget=block"
    else
        record "U-03-IMPLICIT" "FAIL" "USBGuard ImplicitPolicyTarget not set to block"
    fi
else
    record "U-03-STORAGE"   "FAIL" "USBGuard rules.conf not found"
    record "U-03-COMPOSITE" "FAIL" "USBGuard rules.conf not found"
    record "U-03-HID"       "FAIL" "USBGuard rules.conf not found"
    record "U-03-IMPLICIT"  "FAIL" "USBGuard rules.conf not found"
fi

# ---------------------------------------------------------------------------
# U-04: udev rules — mass storage authorization=0
# ---------------------------------------------------------------------------
if [ -f "$UDEV_RULE" ]; then
    if grep -q 'ATTR{bInterfaceClass}=="08".*authorized.*=.*"0"' "$UDEV_RULE" || \
       grep -q '"08".*authorized.*"0"' "$UDEV_RULE"; then
        record "U-04" "PASS" "udev rule blocks USB Mass Storage (class 08, authorized=0)"
    else
        record "U-04" "FAIL" "udev rule missing authorized=0 for storage class"
    fi
else
    record "U-04" "BLOCKED" "udev USB rule file not found: ${UDEV_RULE}"
fi

# ---------------------------------------------------------------------------
# U-05 (Hardware only): Plug/unplug event logging
# ---------------------------------------------------------------------------
if [ "$HARDWARE_TEST" = "1" ]; then
    echo "[USB] Monitoring USB events for 30 seconds (plug test devices now)..."
    sleep 30
    USB_EVENTS=$(journalctl -n 100 --since "1 minute ago" 2>/dev/null | grep -i "ExamOS-USB\|usbguard\|authorized" || true)
    if [ -n "$USB_EVENTS" ]; then
        record "U-05" "PASS" "USB events logged: $(echo "$USB_EVENTS" | wc -l) entries"
        echo "$USB_EVENTS" >> "$ARTIFACT_DIR/usb-event-log.txt"
    else
        record "U-05" "FAIL" "No USB events logged during test window"
    fi
else
    record "U-05" "BLOCKED" "BLOCKED_ENVIRONMENT: hardware test not enabled (set HARDWARE_TEST=1)"
fi

# ---------------------------------------------------------------------------
# Write results
# ---------------------------------------------------------------------------
{
    printf '{"timestamp":"%s","pass":%d,"fail":%d,"blocked":%d,"overall":"%s"}\n' \
        "$(ts)" "$PASS" "$FAIL" "$BLOCKED" "$(overall_status)"
} > "$ARTIFACT_DIR/usb-policy-tests.json"

echo ""
echo "=== [P2-USB] PASS=${PASS} FAIL=${FAIL} BLOCKED=${BLOCKED} ==="
[ "$FAIL" -eq 0 ]
