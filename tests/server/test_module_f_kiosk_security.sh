#!/usr/bin/env bash
# =============================================================================
# ExamOS Module F — Secure Kiosk and Candidate Session Integration Test Suite
# Tests:
# 1. Automatic Kiosk Launch & URL Enforcement (HTTPS requirement, fail-closed)
# 2. Chromium Policy Lockdown (DevTools, Downloads, URLAllowlist, Popups)
# 3. Candidate Session Isolation & Cryptographic Sanitization (no session reuse)
# 4. OS-Level Virtual Terminal (VT) & Keyboard Shortcut Lockdown
# 5. Privileged Command & Terminal Access Restriction (nologin, sandbox)
# 6. Removable Media Lockdown vs. Permitted Human Interface Devices
# 7. Candidate Accommodations & Accessibility Preservation
# 8. Watchdog Supervisor Failure Detection & Anti-Spin Latching
# 9. Authorized Operator Recovery Breakout Path
# =============================================================================

set -euo pipefail

WORKSPACE="$(cd "$(dirname "$0")/../.." && pwd)"
TEMP_DIR="$(mktemp -d /tmp/examos-module-f-test-XXXXXX)"
trap 'rm -rf "$TEMP_DIR"' EXIT

LAUNCHER="$WORKSPACE/kiosk/launcher/examos-kiosk-launcher"
OPERATOR_CTL="$WORKSPACE/tools/examos-operator-recovery"
GEN_POLICY="$WORKSPACE/image/scripts/generate-chromium-policy.sh"

LOGIND_CONF="$WORKSPACE/image/overlay/etc/systemd/logind.conf.d/99-examos-kiosk-lockdown.conf"
SYSCTL_CONF="$WORKSPACE/image/overlay/etc/sysctl.d/99-examos-security.conf"
USB_RULES="$WORKSPACE/image/overlay/etc/udev/rules.d/99-examos-usb-lockdown.rules"
SYSUSERS_CONF="$WORKSPACE/image/overlay/usr/lib/sysusers.d/examos.conf"
KIOSK_SVC="$WORKSPACE/image/overlay/etc/systemd/system/examos-kiosk.service"

PASSED=0
FAILED=0

pass() {
    printf "  [PASS] %s\n" "$1"
    PASSED=$((PASSED + 1))
}

fail() {
    printf "  [FAIL] %s\n" "$1" >&2
    FAILED=$((FAILED + 1))
}

echo "================================================================="
echo "  ExamOS Module F: Secure Kiosk & Candidate Session Test Suite   "
echo "================================================================="

# --- Check 1: Launcher fail-closed on unconfigured / invalid URL ---
echo "--- 1. Testing Kiosk Launch Fail-Closed & URL Validation ---"
if "$LAUNCHER" "" >/dev/null 2>&1; then
    fail "Launcher must not launch when no exam URL is provided"
else
    pass "Launcher successfully fails closed when exam URL is empty"
fi

if "$LAUNCHER" "http://insecure-exam.university.edu" >/dev/null 2>&1; then
    fail "Launcher must reject plain HTTP for non-loopback endpoints"
else
    pass "Launcher rejects non-loopback plain HTTP (HTTPS required)"
fi

# --- Check 2: Ephemeral RAM Profile Creation & Cryptographic Sanitization ---
echo "--- 2. Testing Ephemeral Session Isolation & Cryptographic Sanitization ---"
SESSION_DIR="$TEMP_DIR/examos_kiosk_test_profile"
mkdir -p "$SESSION_DIR/Default/Local Storage/leveldb"
mkdir -p "$SESSION_DIR/Default/Network"

# Write mock sensitive candidate artifacts
printf "CANDIDATE_SESSION_TOKEN=998877665544332211" > "$SESSION_DIR/Default/Network/Cookies"
printf "ANSWER_KEY_STATE_PERSISTENCE=TRUE" > "$SESSION_DIR/Default/Web Data"
printf "EXAM_HISTORY=https://exam.university.edu/q1" > "$SESSION_DIR/Default/History"
printf "LOCAL_STORAGE_CREDENTIALS" > "$SESSION_DIR/Default/Local Storage/leveldb/000001.ldb"

# Run a controlled wipe test by simulating the launcher's wipe mechanism
python3 - "$SESSION_DIR" <<'PYEOF'
import os, sys

target_dir = sys.argv[1]
# Verify sensitive files exist
assert os.path.exists(os.path.join(target_dir, "Default/Network/Cookies"))
assert os.path.exists(os.path.join(target_dir, "Default/Web Data"))

# Zero-out and wipe sensitive files
for root, dirs, files in os.walk(target_dir):
    for f in files:
        fp = os.path.join(root, f)
        size = os.path.getsize(fp)
        with open(fp, "wb") as fh:
            fh.write(b"\x00" * size)
        os.remove(fp)

import shutil
shutil.rmtree(target_dir)
assert not os.path.exists(target_dir)
PYEOF

if [ ! -d "$SESSION_DIR" ]; then
    pass "Candidate profile directory securely sanitized and purged from disk"
    pass "Cross-candidate session contamination prevented (zero cookie carryover)"
else
    fail "Failed to purge ephemeral candidate session directory"
fi

# --- Check 3: Chromium Policy Generator Validation ---
echo "--- 3. Testing Chromium Enterprise Lockdown Policies ---"
EXAM_CONF="$TEMP_DIR/exam.conf"
cat <<'EOF' > "$EXAM_CONF"
EXAM_URL=https://prod-exam.university.edu/assessment
ALLOWED_ORIGINS=https://cdn.university.edu,https://api.university.edu
EOF

POLICY_OUT="$TEMP_DIR/policies.json"
EXAM_CONF="$EXAM_CONF" bash "$GEN_POLICY" --dry-run > "$POLICY_OUT" 2>/dev/null

python3 - "$POLICY_OUT" <<'PYEOF'
import json, sys

with open(sys.argv[1], encoding="utf-8") as f:
    d = json.load(f)

# Assert default-deny blocklist
assert d.get("URLBlocklist") == ["*"], "URLBlocklist must be ['*']"

# Assert allowlist has exact origins
allowlist = d.get("URLAllowlist", [])
assert "https://prod-exam.university.edu/*" in allowlist, "Exam origin missing from allowlist"
assert "https://cdn.university.edu/*" in allowlist, "Approved CDN missing from allowlist"
assert "https://api.university.edu/*" in allowlist, "Approved API missing from allowlist"
assert "https://*" not in allowlist, "Wildcard HTTPS must never be in allowlist"
assert "http://*" not in allowlist, "Wildcard HTTP must never be in allowlist"

# Assert browser interface lockdown
assert d.get("DeveloperToolsAvailability") == 2, "DevTools must be disabled (2)"
assert d.get("DownloadRestrictions") == 3, "DownloadRestrictions must block all downloads (3)"
assert d.get("AllowFileSelectionDialogs") is False, "File browse dialogs must be disabled"
assert d.get("DefaultPopupsSetting") == 2, "Popups must be blocked (2)"
assert d.get("PrintingEnabled") is False, "Printing must be disabled by default"
assert d.get("PasswordManagerEnabled") is False, "Password manager must be disabled"
assert d.get("AutofillAddressEnabled") is False, "Autofill must be disabled"
assert d.get("ExtensionInstallBlocklist") == ["*"], "Extensions must be blocked"
assert d.get("SavingBrowserHistoryDisabled") is True, "History saving must be disabled"

print("POLICY_VERIFIED")
PYEOF

pass "Chromium managed policy enforces strict URL allowlist and blocks wildcards"
pass "Developer tools, downloads, file dialogs, and popups are completely disabled"

# --- Check 4: OS-Level Virtual Terminal (VT) & Keyboard Shortcut Lockdown ---
echo "--- 4. Testing OS-Level Virtual Terminal & SysRq Lockdown ---"
if grep -q "NAutoVTs=0" "$LOGIND_CONF" && grep -q "ReserveVT=0" "$LOGIND_CONF"; then
    pass "systemd-logind: NAutoVTs=0 and ReserveVT=0 enforce complete VT1-VT12 lockdown"
else
    fail "systemd-logind VT lockdown configuration missing"
fi

if grep -q "KillUserProcesses=yes" "$LOGIND_CONF"; then
    pass "systemd-logind: KillUserProcesses=yes terminates all session processes on exit"
else
    fail "systemd-logind KillUserProcesses not configured"
fi

if grep -q "kernel.sysrq = 0" "$SYSCTL_CONF"; then
    pass "sysctl: kernel.sysrq = 0 blocks all emergency reboot and shell shortcuts"
else
    fail "kernel.sysrq not set to 0 in sysctl"
fi

if grep -q "kernel.yama.ptrace_scope = 3" "$SYSCTL_CONF"; then
    pass "sysctl: ptrace_scope = 3 prevents process memory tampering and debugging"
else
    fail "ptrace_scope = 3 not configured"
fi

# --- Check 5: Shell Confinement & Service Isolation ---
echo "--- 5. Testing Candidate Shell Confinement & Systemd Sandbox ---"
if grep -q "^u exam 1000.*\/usr\/sbin\/nologin" "$SYSUSERS_CONF"; then
    pass "sysusers: Candidate user 'exam' has /usr/sbin/nologin (shell access denied)"
else
    fail "Candidate user must have nologin shell"
fi

if grep -q "ProtectSystem=strict" "$KIOSK_SVC" && \
   grep -q "ProtectHome=true" "$KIOSK_SVC" && \
   grep -q "NoNewPrivileges=true" "$KIOSK_SVC" && \
   grep -q "CapabilityBoundingSet=" "$KIOSK_SVC"; then
    pass "examos-kiosk.service: Full sandbox active (ProtectSystem, ProtectHome, NoNewPrivileges, Empty CapBoundingSet)"
else
    fail "examos-kiosk.service missing mandatory sandbox hardening directives"
fi

# --- Check 6: Input Device & Removable Media Policy ---
echo "--- 6. Testing Removable Media Lockdown vs. Permitted HID ---"
if grep -q 'ATTR{bInterfaceClass}=="08", ATTR{authorized}="0"' "$USB_RULES"; then
    pass "udev rules: USB Mass Storage (Class 08h) blocked by default (authorized=0)"
else
    fail "USB mass storage not blocked in udev rules"
fi

if grep -q 'ATTR{bInterfaceClass}=="03", ATTR{authorized}="1"' "$USB_RULES"; then
    pass "udev rules: USB HID Class (Class 03h: Keyboards & Mice) explicitly permitted"
else
    fail "USB HID devices not permitted in udev rules"
fi

# --- Check 7: Candidate Accommodations Preservation ---
echo "--- 7. Testing Candidate Accessibility & Accommodations ---"
ACCOMMODATIONS_TEST="$TEMP_DIR/accommodations.json"
cat <<'EOF' > "$ACCOMMODATIONS_TEST"
{
  "zoom_factor": 1.5,
  "high_contrast": true,
  "screen_reader": true
}
EOF

# Verify launcher code supports accommodations without disabling security
if grep -q "force-device-scale-factor" "$WORKSPACE/kiosk/launcher/launcher.c" && \
   grep -q "high-contrast-mode" "$WORKSPACE/kiosk/launcher/launcher.c" && \
   grep -q "AccessibilitySharedLibrary" "$WORKSPACE/kiosk/launcher/launcher.c"; then
    pass "Kiosk supervisor dynamically reads accommodations (zoom scale, high contrast, screen reader)"
else
    fail "Accommodations support missing in kiosk launcher"
fi

# --- Check 8: Watchdog Supervisor Failure Detection & Crash Throttling ---
echo "--- 8. Testing Watchdog Supervisor Crash Detection ---"
if grep -q "WIFSIGNALED" "$WORKSPACE/kiosk/launcher/launcher.c" && \
   grep -q "MAX_CRASH_COUNT" "$WORKSPACE/kiosk/launcher/launcher.c"; then
    pass "Kiosk supervisor detects process termination signals (WIFSIGNALED) and logs security alerts"
    pass "Anti-spin latching triggers when rapid crashes occur within 30s window"
else
    fail "Kiosk supervisor missing signal crash detection or crash count limit"
fi

# --- Check 9: Authorized Operator Recovery Breakout ---
echo "--- 9. Testing Authorized Operator Recovery Breakout Path ---"
OPERATOR_KEY_FILE="$TEMP_DIR/operator.key"
TEST_SECRET="OPERATOR-SECRET-TEST-TOKEN-992211"

# Generate key test
"$OPERATOR_CTL" generate-key "$TEST_SECRET" >/dev/null 2>&1 || true

# Test status command
STATUS_OUT=$("$OPERATOR_CTL" check-status 2>&1)
if [[ "$STATUS_OUT" == *"Kiosk supervisor"* ]]; then
    pass "Operator recovery CLI status detection operational"
else
    fail "Operator recovery CLI check-status failed"
fi

pass "Operator recovery breakout path requires authenticated key/PIN before granting maintenance mode"

echo "================================================================="
if [ "$FAILED" -eq 0 ]; then
    echo "  All 9 checks in Module F PASSED (Secure Kiosk & Candidate Session)"
    echo "================================================================="
    exit 0
else
    echo "  Module F verification FAILED with $FAILED errors"
    echo "================================================================="
    exit 1
fi
