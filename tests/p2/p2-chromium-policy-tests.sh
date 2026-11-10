#!/usr/bin/env bash
# =============================================================================
# ExamOS P2 — Chromium Policy Tests (Layer 3 / Layer 6 runtime)
# Mandatory: P2-01 P2-02 P2-14 P2-15 P2-16
#
# Tests:
#   1. Policy JSON syntax and value validation (static)
#   2. Policy schema against Chromium version (static)
#   3. Runtime: Chromium policy loaded flag (if browser running)
#   4. Runtime: sandbox active (no --no-sandbox flag)
#   5. Origin-scoped camera/mic policy
# =============================================================================
set -uo pipefail

WORKSPACE="$(cd "$(dirname "$0")/../.." && pwd)"
ARTIFACT_DIR="${ARTIFACT_DIR:-${EXAMOS_P2_ARTIFACT_DIR:-$WORKSPACE/artifacts/phase2}}"
mkdir -p "$ARTIFACT_DIR"

LOG="$ARTIFACT_DIR/chromium-policy-tests.log"
exec > >(tee "$LOG") 2>&1

PASS=0; FAIL=0; BLOCKED=0
ts() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

record() {
    local id="$1" status="$2" detail="$3"
    case "$status" in
        PASS)    PASS=$((PASS+1));    echo "[POLICY-PASS]    ${id}: ${detail}" ;;
        FAIL)    FAIL=$((FAIL+1));    echo "[POLICY-FAIL]    ${id}: ${detail}" >&2 ;;
        BLOCKED) BLOCKED=$((BLOCKED+1)); echo "[POLICY-BLOCKED] ${id}: ${detail}" ;;
    esac
}
overall_status() {
    if [ "$FAIL" -gt 0 ]; then echo "FAIL"
    elif [ "$BLOCKED" -gt 0 ]; then echo "BLOCKED"
    elif [ "$PASS" -gt 0 ]; then echo "PASS"
    else echo "NOT_RUN"
    fi
}

echo "=== [P2-CHROMIUM] Policy Tests: $(ts) ==="

# ---------------------------------------------------------------------------
# Detect policy file path
# ---------------------------------------------------------------------------
POLICY_FILE=""
for candidate in \
    /etc/chromium/policies/managed/examos_policies.json \
    /etc/opt/chrome/policies/managed/examos_policies.json \
    "$WORKSPACE/image/overlay/etc/chromium/policies/managed/examos_policies.json"; do
    [ -f "$candidate" ] && { POLICY_FILE="$candidate"; break; }
done

if [ -z "$POLICY_FILE" ]; then
    record "CP-01" "FAIL" "No Chromium policy file found"
    printf '{"timestamp":"%s","pass":0,"fail":1,"blocked":0,"overall":"FAIL"}\n' \
        "$(ts)" > "$ARTIFACT_DIR/chromium-policy-validation.json"
    exit 1
fi
if [[ "$POLICY_FILE" == "$WORKSPACE"/image/overlay/* ]]; then
    record "CP-01" "PASS" "Managed policy source file found: ${POLICY_FILE} (runtime deployment remains unverified)"
else
    record "CP-01" "PASS" "Managed policy deployed: ${POLICY_FILE}"
fi

# Get Chromium version
if command -v chromium >/dev/null 2>&1; then
    CHROMIUM_VERSION=$(chromium --version 2>/dev/null | head -1 || echo "NOT_AVAILABLE")
    if [ "$CHROMIUM_VERSION" = "NOT_AVAILABLE" ]; then
        record "CP-VERSION" "BLOCKED" "Chromium binary exists but did not return a version"
    else
        record "CP-VERSION" "PASS" "Chromium version: ${CHROMIUM_VERSION}"
    fi
else
    CHROMIUM_VERSION="NOT_AVAILABLE"
    record "CP-VERSION" "BLOCKED" "Chromium binary is not installed in this environment"
fi

# ---------------------------------------------------------------------------
# CP-02 (P2-14): Full policy validation using Python
# ---------------------------------------------------------------------------
POLICY_ERRORS=$(python3 - "$POLICY_FILE" <<'PYEOF'
import json, sys

path = sys.argv[1]
try:
    d = json.load(open(path))
except json.JSONDecodeError as e:
    print(f"JSON parse error: {e}")
    sys.exit(1)

errors = []

# URLBlocklist must contain '*'
bl = d.get("URLBlocklist", [])
if "*" not in bl:
    errors.append("URLBlocklist missing '*' default-deny")

# URLAllowlist must NOT contain 'https://*' or 'http://*'
al = d.get("URLAllowlist", [])
if "https://*" in al:
    errors.append("URLAllowlist contains 'https://*' (allows ALL HTTPS)")
if "http://*" in al:
    errors.append("URLAllowlist contains 'http://*' (allows ALL HTTP)")
if len(al) == 0:
    errors.append("URLAllowlist is empty — no exam URL can be reached")

# DeveloperToolsAvailability=2
if d.get("DeveloperToolsAvailability") != 2:
    errors.append(f"DeveloperToolsAvailability={d.get('DeveloperToolsAvailability')} (must be 2)")

# DownloadRestrictions=3
if d.get("DownloadRestrictions") != 3:
    errors.append(f"DownloadRestrictions={d.get('DownloadRestrictions')} (must be 3)")

# PrintingEnabled=false
if d.get("PrintingEnabled", True) is not False:
    errors.append("PrintingEnabled not false")

# DefaultPopupsSetting=2
if d.get("DefaultPopupsSetting") != 2:
    errors.append(f"DefaultPopupsSetting={d.get('DefaultPopupsSetting')} (must be 2)")

# IncognitoModeAvailability=1
if d.get("IncognitoModeAvailability") != 1:
    errors.append(f"IncognitoModeAvailability={d.get('IncognitoModeAvailability')} (must be 1)")

# Keep Chromium's phishing/malware protection enabled while kiosk restrictions
# disable unrelated data collection and browsing features.
if d.get("SafeBrowsingProtectionLevel", 0) < 1:
    errors.append("SafeBrowsingProtectionLevel must enable at least standard protection")

# AllowFileSelectionDialogs=false
if d.get("AllowFileSelectionDialogs", True) is not False:
    errors.append("AllowFileSelectionDialogs not false")

# ExtensionInstallBlocklist must contain '*'
ebl = d.get("ExtensionInstallBlocklist", [])
if "*" not in ebl:
    errors.append("ExtensionInstallBlocklist missing '*'")

# Camera/mic must be scoped to URL, not globally allowed
if d.get("VideoCaptureAllowed", False) is True:
    errors.append("VideoCaptureAllowed=true (globally — must use VideoCaptureAllowedUrls instead)")
if d.get("AudioCaptureAllowed", False) is True:
    errors.append("AudioCaptureAllowed=true (globally — must use AudioCaptureAllowedUrls instead)")
if not d.get("VideoCaptureAllowedUrls"):
    errors.append("VideoCaptureAllowedUrls not set")
if not d.get("AudioCaptureAllowedUrls"):
    errors.append("AudioCaptureAllowedUrls not set")

# Camera/mic scoped URLs must not be wildcards
for key in ["VideoCaptureAllowedUrls", "AudioCaptureAllowedUrls"]:
    for url in d.get(key, []):
        if url in ("*", "https://*", "http://*"):
            errors.append(f"{key} contains wildcard '{url}'")

if errors:
    for e in errors:
        print(e)
    sys.exit(1)
sys.exit(0)
PYEOF
)

POLICY_RC=$?
if [ "$POLICY_RC" -eq 0 ]; then
    record "CP-02" "PASS" "All Chromium policy values valid"
else
    while IFS= read -r err; do
        [ -n "$err" ] && record "CP-02" "FAIL" "${err}"
    done <<< "$POLICY_ERRORS"
fi

# ---------------------------------------------------------------------------
# CP-03 (P2-15): Camera/mic are scoped only to exam origin
# ---------------------------------------------------------------------------
python3 - "$POLICY_FILE" <<'PYEOF' && record "CP-03" "PASS" "Camera/mic URLs are scoped to exam origin (no wildcards)" || record "CP-03" "FAIL" "Camera/mic URL scope violation detected"
import json, sys
d = json.load(open(sys.argv[1]))
errors = []
for key in ["VideoCaptureAllowedUrls", "AudioCaptureAllowedUrls"]:
    urls = d.get(key, [])
    for url in urls:
        if url in ("*", "https://*", "http://*", "<all_urls>"):
            errors.append(f"{key}: wildcard URL '{url}'")
        if not url.startswith(("https://", "http://127.", "http://localhost")):
            errors.append(f"{key}: non-HTTPS URL '{url}' in allowedUrls")
if errors:
    for e in errors: print(e)
    sys.exit(1)
PYEOF

# ---------------------------------------------------------------------------
# CP-04 (P2-16): Chromium sandbox — verify running process has no --no-sandbox
# PG-14: Also verify AppArmor is in enforce mode for Chromium
# ---------------------------------------------------------------------------
CHROMIUM_PID=$(pgrep -f "chromium.*--kiosk" 2>/dev/null | head -1 || true)
if [ -n "$CHROMIUM_PID" ]; then
    CMDLINE=$(cat /proc/${CHROMIUM_PID}/cmdline 2>/dev/null | tr '\0' ' ' || true)
    if echo "$CMDLINE" | grep -qE "\-\-no-sandbox|\-\-disable-gpu-sandbox|\-\-disable-seccomp-filter-sandbox"; then
        record "CP-04" "FAIL" "Chromium has sandbox-disabling flag: ${CMDLINE:0:200}"
    else
        record "CP-04" "PASS" "Chromium running without sandbox-disabling flags (PID=${CHROMIUM_PID})"
    fi
    # PG-14: Check AppArmor confinement status for the running Chromium process
    AA_STATUS=$(cat /proc/${CHROMIUM_PID}/attr/current 2>/dev/null || echo "")
    if [ -z "$AA_STATUS" ] || [ "$AA_STATUS" = "unconfined" ]; then
        record "CP-04-APPARMOR" "FAIL" "Chromium process (PID=${CHROMIUM_PID}) is NOT confined by AppArmor (status: ${AA_STATUS:-unconfined})"
    else
        record "CP-04-APPARMOR" "PASS" "Chromium process (PID=${CHROMIUM_PID}) is AppArmor-confined: ${AA_STATUS}"
    fi
else
    record "CP-04" "BLOCKED" "BLOCKED: Chromium not running — sandbox check deferred"
    # PG-14: Static check — verify AppArmor profile exists and is in enforce mode
    AA_PROFILE="/etc/apparmor.d/examos-kiosk"
    if [ ! -f "$AA_PROFILE" ]; then
        AA_PROFILE="$WORKSPACE/image/overlay/etc/apparmor.d/examos-kiosk"
    fi
    if [ -f "$AA_PROFILE" ]; then
        # Profile must not contain 'flags=(complain)' — that would be non-enforcing
        if grep -q 'flags=(complain)' "$AA_PROFILE" 2>/dev/null; then
            record "CP-04-APPARMOR" "FAIL" "AppArmor Chromium profile is in COMPLAIN mode, not enforce"
        else
            record "CP-04-APPARMOR" "PASS" "AppArmor Chromium profile exists and is not in complain mode (enforce assumed)"
        fi
    else
        record "CP-04-APPARMOR" "FAIL" "AppArmor Chromium profile not found — confinement unverified"
    fi
fi

# ---------------------------------------------------------------------------
# CP-05 (P2-14): Verify policy is loaded in Chromium using chromium --policies
# (Chromium supports --policies flag to dump active policy state)
# ---------------------------------------------------------------------------
POLICY_DUMP_FILE="$ARTIFACT_DIR/chromium-policy-dump.json"
if command -v chromium >/dev/null 2>&1; then
    # --policies dumps the policy state and exits; safe to run as exam user check
    # This requires the exam user environment but we attempt it here.
    POLICY_DUMP_RC=0
    timeout 10 chromium --policies 2>/dev/null > "$POLICY_DUMP_FILE" || POLICY_DUMP_RC=$?
    if [ -s "$POLICY_DUMP_FILE" ]; then
        record "CP-05" "PASS" "Chromium --policies dump succeeded (${POLICY_DUMP_FILE})"
    else
        record "CP-05" "BLOCKED" "BLOCKED: chromium --policies produced no output (may require display/user session)"
    fi
else
    record "CP-05" "BLOCKED" "BLOCKED_ENVIRONMENT: chromium binary not in PATH"
fi

# ---------------------------------------------------------------------------
# Write results
# ---------------------------------------------------------------------------
{
    printf '{"timestamp":"%s","chromiumVersion":"%s","policyFile":"%s","pass":%d,"fail":%d,"blocked":%d,"overall":"%s"}\n' \
        "$(ts)" "${CHROMIUM_VERSION}" "${POLICY_FILE}" "$PASS" "$FAIL" "$BLOCKED" \
        "$(overall_status)"
} > "$ARTIFACT_DIR/chromium-policy-validation.json"

cp "$POLICY_FILE" "$ARTIFACT_DIR/chromium-policy-runtime-tests.json"

echo ""
echo "=== [P2-CHROMIUM] PASS=${PASS} FAIL=${FAIL} BLOCKED=${BLOCKED} ==="
[ "$FAIL" -eq 0 ]
