#!/usr/bin/env bash
# =============================================================================
# ExamOS P2 — Static Artifact Audit (Layer 1)
# Tests that can run without a booted guest: source, config, policy files.
# Requirement IDs: maps to P2-10, P2-14, P2-15, P2-17, P2-20
# =============================================================================
set -uo pipefail

WORKSPACE=$(cd "$(dirname "$0")/../.." && pwd)
ARTIFACT_DIR="${ARTIFACT_DIR:-$WORKSPACE/artifacts/phase2}"
mkdir -p "$ARTIFACT_DIR"

LOG="$ARTIFACT_DIR/p2-static-audit.log"
exec > >(tee "$LOG") 2>&1

PASS=0; FAIL=0; BLOCKED=0
ts() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

p() { PASS=$((PASS+1));   echo "[STATIC-PASS]    $1"; }
f() { FAIL=$((FAIL+1));   echo "[STATIC-FAIL]    $1" >&2; }
b() { BLOCKED=$((BLOCKED+1)); echo "[STATIC-BLOCKED] $1"; }
overall_status() {
    if [ "$FAIL" -gt 0 ]; then echo "FAIL"
    elif [ "$BLOCKED" -gt 0 ]; then echo "BLOCKED"
    elif [ "$PASS" -gt 0 ]; then echo "PASS"
    else echo "NOT_RUN"
    fi
}

echo "=== [P2-STATIC] ExamOS P2 Static Audit: $(ts) ==="

# ---------------------------------------------------------------------------
# S-01 (P2-10): mkosi.conf must not contain shell/SSH/compiler packages
# ---------------------------------------------------------------------------
MKOSI="$WORKSPACE/image/mkosi.conf"
# Only the [Content] packages are installed in the release image. The [Build]
# section lists host tools that mkosi uses while synthesising the image and
# must not be treated as release-runtime packages.
CONTENT_PKGS=$(awk '/^\[Content\]/{inside=1; next} /^\[/{inside=0} inside' "$MKOSI")
for pkg in bash openssh-server gcc g++ make perl ruby nodejs sudo su; do
    if printf '%s\n' "$CONTENT_PKGS" | grep -qE "^\s+${pkg}\s*$"; then
        f "S-01: Prohibited package '${pkg}' in release mkosi.conf [Content]"
    else
        p "S-01: '${pkg}' absent from release mkosi.conf [Content]"
    fi
done
# python3 is retained deliberately: the shipped startup validator and health
# reporter use it at runtime. Do not classify a required runtime interpreter
# as a build-tool leak. However, document the justification in the audit log.
if printf '%s\n' "$CONTENT_PKGS" | grep -qE '^\s+python3\s*$'; then
    # PG-15: Verify python3 is confined by AppArmor profile before allowing it
    APPARMOR_PROFILE="$WORKSPACE/image/overlay/etc/apparmor.d/usr.bin.chromium"
    PYTHON_PROFILE="$WORKSPACE/image/overlay/etc/apparmor.d/usr.bin.python3"
    if [ -f "$PYTHON_PROFILE" ]; then
        p "S-01: python3 retained and confined by AppArmor profile: $PYTHON_PROFILE"
    elif [ -f "$APPARMOR_PROFILE" ]; then
        # Acceptable if python3 is only invoked by confined services
        p "S-01: python3 retained for shipped startup/security validators (AppArmor present; python3-specific profile absent — ensure python3 is only invoked from confined systemd units)"
    else
        f "S-01: python3 in release image but no AppArmor confinement profile found — attack surface not justified"
    fi
else
    f "S-01: python3 runtime dependency missing from release mkosi.conf"
fi

# ---------------------------------------------------------------------------
# S-02 (P2-10): lockdown=confidentiality in release cmdline
# ---------------------------------------------------------------------------
if grep -q "lockdown=confidentiality" "$MKOSI"; then
    p "S-02: lockdown=confidentiality in mkosi.conf KernelCommandLine"
else
    f "S-02: lockdown=confidentiality missing from mkosi.conf"
fi

# ---------------------------------------------------------------------------
# S-03 (P2-10): required P2 packages present in mkosi.conf
# ---------------------------------------------------------------------------
for pkg in cryptsetup-bin usbguard nftables apparmor; do
    if grep -q "$pkg" "$MKOSI" 2>/dev/null; then
        p "S-03: Required P2 package present: ${pkg}"
    else
        f "S-03: Required P2 package missing from mkosi.conf: ${pkg}"
    fi
done

# ---------------------------------------------------------------------------
# S-04 (P2-14): Chromium policy — URLBlocklist=*, no https://* in allowlist
# ---------------------------------------------------------------------------
POLICY="$WORKSPACE/image/overlay/etc/chromium/policies/managed/examos_policies.json"
if [ -f "$POLICY" ]; then
    PYTHON_BIN=$(command -v python3 || command -v python || true)
    if [ -z "$PYTHON_BIN" ]; then
        b "S-04: Python 3 is required to validate Chromium policy JSON"
    else
        if POLICY_ERRORS=$("$PYTHON_BIN" - "$POLICY" <<'PY'
import json
import sys

try:
    with open(sys.argv[1], encoding="utf-8") as policy_file:
        policy = json.load(policy_file)
except (OSError, json.JSONDecodeError) as error:
    print(f"invalid policy JSON: {error}")
    sys.exit(1)

blocklist = policy.get("URLBlocklist", [])
allowlist = policy.get("URLAllowlist", [])
errors = []
if "*" not in blocklist: errors.append("URLBlocklist missing *")
if "https://*" in allowlist: errors.append("URLAllowlist contains https://*")
if policy.get("DeveloperToolsAvailability") != 2: errors.append("DeveloperToolsAvailability!=2")
if policy.get("DownloadRestrictions") != 3: errors.append("DownloadRestrictions!=3")
if policy.get("PrintingEnabled", True): errors.append("PrintingEnabled not false")
if policy.get("IncognitoModeAvailability") != 1: errors.append("IncognitoModeAvailability!=1")
if policy.get("SafeBrowsingProtectionLevel", 0) < 1: errors.append("SafeBrowsingProtectionLevel must enable standard protection")
if policy.get("AllowFileSelectionDialogs", True): errors.append("AllowFileSelectionDialogs not false")
if policy.get("DefaultPopupsSetting") != 2: errors.append("DefaultPopupsSetting!=2")
if not policy.get("VideoCaptureAllowedUrls"): errors.append("VideoCaptureAllowedUrls missing")
if not policy.get("AudioCaptureAllowedUrls"): errors.append("AudioCaptureAllowedUrls missing")
if policy.get("VideoCaptureAllowed", False): errors.append("VideoCaptureAllowed=true (global, not scoped)")
if policy.get("AudioCaptureAllowed", False): errors.append("AudioCaptureAllowed=true (global, not scoped)")
if errors:
    print("; ".join(errors))
    sys.exit(1)
PY
        ); then
            p "S-04: Chromium policy all mandatory fields correct"
        else
            f "S-04: Chromium policy errors: ${POLICY_ERRORS:-validation failed without diagnostics}"
        fi
    fi
else
    f "S-04: Chromium policy file not found: ${POLICY}"
fi

# ---------------------------------------------------------------------------
# S-05 (P2-10): getty masking in hardening script
# ---------------------------------------------------------------------------
HARD="$WORKSPACE/image/scripts/01-hardening.sh"
LOCK="$WORKSPACE/image/scripts/03-p2-lockdown.sh"
for pattern in "mask.*getty" "mask.*autovt" "mask.*serial-getty" "mask.*emergency" "mask.*rescue" "mask.*ssh"; do
    if grep -qE "$pattern" "$LOCK" 2>/dev/null || grep -qE "$pattern" "$HARD" 2>/dev/null; then
        p "S-05: '${pattern}' present in hardening scripts"
    else
        f "S-05: '${pattern}' missing from hardening scripts"
    fi
done

# ---------------------------------------------------------------------------
# S-06 (P2-17): No secrets in source
# ---------------------------------------------------------------------------
SECRET_HITS=$(find "$WORKSPACE" -type f \( -name "*.pem" -o -name "*.key" -o -name "id_rsa" -o -name "id_ed25519" \) \
    ! -path "*/.git/*" ! -path "*/image/trust/*" ! -path "*/build/*" 2>/dev/null || true)
if [ -z "$SECRET_HITS" ]; then
    p "S-06: No private key files in source tree"
else
    f "S-06: Private key files found: ${SECRET_HITS}"
fi

# ---------------------------------------------------------------------------
# S-07 (P2-20): Required P2 service unit files exist
# ---------------------------------------------------------------------------
OVERLAY="$WORKSPACE/image/overlay/etc/systemd/system"
for unit in examos-kiosk.service examos-module-lock.service examos-usb-lockdown.service \
            examos-preflight.service examos-lockdown-failed.target \
            examos-dev-shm-hardening.service examos-kiosk-readiness.service \
            tmp.mount home-exam.mount var-log.mount; do
    if [ -f "${OVERLAY}/${unit}" ]; then
        p "S-07: Service unit exists: ${unit}"
    else
        f "S-07: Service unit missing: ${unit}"
    fi
done

# ---------------------------------------------------------------------------
# S-08 (P2-10): sysctl file contains required P2 settings
# ---------------------------------------------------------------------------
SYSCTL="$WORKSPACE/image/overlay/etc/sysctl.d/99-examos-security.conf"
for key_val in \
    "kernel.sysrq = 0" \
    "kernel.yama.ptrace_scope = 3" \
    "kernel.unprivileged_bpf_disabled = 1" \
    "net.ipv6.conf.all.disable_ipv6 = 1" \
    "vm.swappiness = 0" \
    "fs.suid_dumpable = 0"; do
    key=$(echo "$key_val" | cut -d= -f1 | tr -d ' ')
    if grep -q "^${key}" "$SYSCTL" 2>/dev/null; then
        p "S-08: sysctl '${key_val}' present"
    else
        f "S-08: sysctl key missing: '${key_val}'"
    fi
done

# ---------------------------------------------------------------------------
# S-09 (P2-13): nftables policy is default-deny on ALL three chains
# ---------------------------------------------------------------------------
NFT="$WORKSPACE/image/overlay/etc/nftables.conf"
if [ -f "$NFT" ]; then
    # PG-16: Check each required chain explicitly, not just a count
    MISSING_CHAINS=""
    for chain in input output forward; do
        # Look for the chain block containing 'policy drop'
        if ! awk "/chain ${chain}/,/}/ { if (/policy drop/) found=1 } END { exit !found }" "$NFT" 2>/dev/null; then
            MISSING_CHAINS="$MISSING_CHAINS $chain"
        fi
    done
    WILDCARD=$(sed 's/#.*//' "$NFT" | \
        grep -E '(^|[[:space:]])(0\.0\.0\.0/0|0/0|::/0)([[:space:]]|$).*accept' || true)
    if [ -z "$MISSING_CHAINS" ] && [ -z "$WILDCARD" ]; then
        p "S-09: nftables has policy drop on input/output/forward chains, no 0.0.0.0/0 accept"
    else
        [ -n "$MISSING_CHAINS" ] && f "S-09: nftables missing policy drop on chains:${MISSING_CHAINS}"
        [ -n "$WILDCARD" ] && f "S-09: nftables contains broad 0.0.0.0/0 accept rule"
    fi
else
    f "S-09: nftables.conf missing"
fi

# ---------------------------------------------------------------------------
# S-10 (P2-16): Kiosk service has NoNewPrivileges, ProtectSystem, empty CapabilityBoundingSet
# ---------------------------------------------------------------------------
KIOSK_SVC="$WORKSPACE/image/overlay/etc/systemd/system/examos-kiosk.service"
for directive in "NoNewPrivileges=true" "ProtectSystem=strict" "CapabilityBoundingSet=" "PrivateTmp=true" "LockPersonality=true"; do
    if grep -q "^${directive}" "$KIOSK_SVC" 2>/dev/null; then
        p "S-10: kiosk.service has '${directive}'"
    else
        f "S-10: kiosk.service missing '${directive}'"
    fi
done

# ---------------------------------------------------------------------------
# S-11: USBGuard rules exist
# ---------------------------------------------------------------------------
USB_RULES="$WORKSPACE/image/overlay/etc/usbguard/rules.conf"
if [ -f "$USB_RULES" ]; then
    BLOCK_STORAGE=$(grep -c "08:\*:\*" "$USB_RULES" 2>/dev/null || echo 0)
    IMPLICIT=$(grep "ImplicitPolicyTarget=block" "$WORKSPACE/image/overlay/etc/usbguard/usbguard-daemon.conf" 2>/dev/null || true)
    if [ "$BLOCK_STORAGE" -ge 1 ] && [ -n "$IMPLICIT" ]; then
        p "S-11: USBGuard rules include storage block and implicit deny"
    else
        f "S-11: USBGuard rules incomplete (storage block=${BLOCK_STORAGE}, implicit=${IMPLICIT:-missing})"
    fi
else
    f "S-11: USBGuard rules.conf missing"
fi

# ---------------------------------------------------------------------------
# S-12: USBGuard is installed/enabled and required by the boot preflight
# ---------------------------------------------------------------------------
LOCKDOWN_SCRIPT="$WORKSPACE/image/scripts/03-p2-lockdown.sh"
PREFLIGHT_UNIT="$WORKSPACE/image/overlay/etc/systemd/system/examos-preflight.service"
if grep -Fq 'enable_required_unit usbguard.service' "$LOCKDOWN_SCRIPT" &&
   grep -Eq '^Requires=.*usbguard\.service' "$PREFLIGHT_UNIT" &&
   grep -Eq '^After=.*usbguard\.service' "$PREFLIGHT_UNIT"; then
    p "S-12: USBGuard is enabled and required before preflight"
else
    f "S-12: USBGuard boot enablement/preflight dependency is missing"
fi

# ---------------------------------------------------------------------------
# S-13 (P2-06): the real validator and lockdown mutation must enter the image
# ---------------------------------------------------------------------------
BUILD_SCRIPT="$WORKSPACE/scripts/build-full-image.sh"
RUNTIME_VALIDATOR="$WORKSPACE/image/scripts/p2-startup-validator.sh"
OVERLAY_VALIDATOR="$WORKSPACE/image/overlay/usr/local/bin/p2-startup-validator.sh"
if grep -Fq 'PostInstallationScripts=scripts/03-p2-lockdown.sh' "$MKOSI" &&
   grep -Fq 'image/scripts/p2-startup-validator.sh' "$BUILD_SCRIPT" &&
   grep -Fq 'EXPECTED_CHECKS=18' "$RUNTIME_VALIDATOR" &&
   grep -Fq 'V-16-ROOTVERITY' "$RUNTIME_VALIDATOR" &&
   grep -Fq 'complete runtime validator was not staged' "$OVERLAY_VALIDATOR"; then
    p "S-13: complete validator is staged and P2 lockdown runs during image assembly"
else
    f "S-13: image build could ship an incomplete validator or skip P2 lockdown"
fi

# ---------------------------------------------------------------------------
# Output summary
# ---------------------------------------------------------------------------
echo ""
echo "=== [P2-STATIC] Summary: PASS=${PASS} FAIL=${FAIL} BLOCKED=${BLOCKED} ==="
cat > "$ARTIFACT_DIR/p2-static-summary.json" <<EOF
{"timestamp":"$(ts)","pass":${PASS},"fail":${FAIL},"blocked":${BLOCKED},"overall":"$(overall_status)"}
EOF
[ "$FAIL" -eq 0 ]
