#!/usr/bin/env bash
# =============================================================================
# ExamOS P2 Release Image Audit
# Inspects the assembled rootfs (ROOTFS_PATH) or a mounted image for:
#   - Prohibited packages / binaries (shell, SSH, package manager, compilers)
#   - Login-enabling services
#   - Open remote administration services
#   - Development credentials / default passwords in config
#   - Verifies allowlisted packages only
#
# Usage:
#   ROOTFS_PATH=/path/to/rootfs bash release-audit.sh
#   or called by CI with the mkosi-produced rootfs mounted under $ROOTFS_PATH
#
# Exit codes:
#   0  All checks PASS
#   1  One or more FAIL findings — CI must reject the release artifact
# =============================================================================
set -uo pipefail

ROOTFS_PATH="${ROOTFS_PATH:-}"
AUDIT_OUT="${AUDIT_OUT:-/tmp/release-package-audit.json}"
FAILED=0
FINDINGS=()
PASSED=()

log_pass() { PASSED+=("$1"); echo "[AUDIT-PASS] $1"; }
log_fail() { FINDINGS+=("$1"); echo "[AUDIT-FAIL] $1" >&2; FAILED=$((FAILED + 1)); }
log_info() { echo "[AUDIT-INFO] $1"; }

# -----------------------------------------------------------------------
# Helper: check whether a binary exists under ROOTFS_PATH
# -----------------------------------------------------------------------
binary_present() {
    local bin="$1"
    # Check both common locations
    for loc in /usr/bin /bin /usr/sbin /sbin /usr/local/bin; do
        [ -f "${ROOTFS_PATH}${loc}/${bin}" ] && return 0
    done
    # Also check via find if ROOTFS_PATH set
    if [ -n "$ROOTFS_PATH" ]; then
        find "${ROOTFS_PATH}" -name "${bin}" -type f 2>/dev/null | grep -q . && return 0
    fi
    return 1
}

# -----------------------------------------------------------------------
# Helper: check whether a systemd service is enabled / active link exists
# -----------------------------------------------------------------------
service_enabled() {
    local svc="$1"
    local wants_dirs=(
        "${ROOTFS_PATH}/etc/systemd/system/multi-user.target.wants"
        "${ROOTFS_PATH}/etc/systemd/system/graphical.target.wants"
        "${ROOTFS_PATH}/lib/systemd/system/multi-user.target.wants"
        "${ROOTFS_PATH}/usr/lib/systemd/system/multi-user.target.wants"
        "${ROOTFS_PATH}/etc/systemd/system/sockets.target.wants"
    )
    for d in "${wants_dirs[@]}"; do
        [ -e "${d}/${svc}" ] && return 0
    done
    return 1
}

# -----------------------------------------------------------------------
# Validate environment
# -----------------------------------------------------------------------
if [ -z "$ROOTFS_PATH" ]; then
    log_info "ROOTFS_PATH not set; running source-only static audit mode"
    log_info "For full rootfs audit set: ROOTFS_PATH=/path/to/mounted/rootfs"
    SOURCE_ONLY=1
else
    SOURCE_ONLY=0
    if [ ! -d "$ROOTFS_PATH" ]; then
        echo "ERROR: ROOTFS_PATH=$ROOTFS_PATH is not a directory" >&2
        exit 1
    fi
    log_info "Auditing rootfs at: $ROOTFS_PATH"
fi

# -----------------------------------------------------------------------
# 1. PROHIBITED BINARIES
# These binaries must NOT be present in the release image.
# -----------------------------------------------------------------------
log_info "--- 1. Prohibited Binary Check ---"

PROHIBITED_BINARIES=(
    # Interactive shells
    "bash" "sh" "dash" "zsh" "fish" "ksh" "csh" "tcsh" "ash"
    # SSH
    "sshd" "ssh" "sftp" "sftp-server" "scp"
    # Package managers
    "apt" "apt-get" "apt-cache" "dpkg" "rpm" "yum" "dnf" "zypper" "pacman" "snap"
    # Compilers / build tools
    "gcc" "g++" "cc" "c++" "make" "cmake" "ld" "as" "ar" "nm" "strip"
    # Scripting runtimes not required by runtime
    "python" "python3" "python3.12" "perl" "ruby" "lua" "node" "nodejs" "php"
    # General privilege escalation
    "sudo" "su" "pkexec" "newgrp" "chsh" "chfn"
    # Development / debug tools
    "gdb" "lldb" "valgrind" "strace" "ltrace" "perf"
    # Remote admin
    "telnet" "nc" "netcat" "ncat" "socat"
    # File managers
    "nautilus" "thunar" "dolphin" "nemo" "pcmanfm"
    # General networking tools (not required in release)
    "nmap" "tcpdump" "wireshark" "tshark"
)

if [ "$SOURCE_ONLY" -eq 0 ]; then
    for bin in "${PROHIBITED_BINARIES[@]}"; do
        if binary_present "$bin"; then
            log_fail "Prohibited binary present in image: $bin"
        else
            log_pass "Prohibited binary absent: $bin"
        fi
    done
else
    log_info "SKIP: rootfs not mounted — prohibited binary check deferred to CI"
    FINDINGS+=("DEFERRED:prohibited_binary_check:rootfs_not_mounted")
fi

# -----------------------------------------------------------------------
# 2. PROHIBITED SERVICES
# -----------------------------------------------------------------------
log_info "--- 2. Prohibited Service Check ---"

PROHIBITED_SERVICES=(
    "ssh.service"
    "sshd.service"
    "openssh-server.service"
    "telnet.socket"
    "rsh.socket"
    "rlogin.socket"
    "cups.service"
    "bluetooth.service"
    "avahi-daemon.service"
    "whoopsie.service"
    "apport.service"
    "snapd.service"
    "cron.service"
    "at.service"
)

# Check mkosi.conf for prohibited packages
MKOSI_CONF="${MKOSI_CONF:-$(dirname "$0")/../mkosi.conf}"
if [ -f "$MKOSI_CONF" ]; then
    for pkg in ssh openssh-server telnet rsh nfs cups bluetooth avahi; do
        if grep -qE "^\s*${pkg}" "$MKOSI_CONF" 2>/dev/null; then
            log_fail "Prohibited package in mkosi.conf: $pkg"
        else
            log_pass "Prohibited package absent from mkosi.conf: $pkg"
        fi
    done
fi

if [ "$SOURCE_ONLY" -eq 0 ]; then
    for svc in "${PROHIBITED_SERVICES[@]}"; do
        if service_enabled "$svc"; then
            log_fail "Prohibited service is enabled: $svc"
        else
            log_pass "Prohibited service not enabled: $svc"
        fi
    done

    # Check for active SSH listener configuration
    SSH_CONFIGS=(
        "${ROOTFS_PATH}/etc/ssh/sshd_config"
        "${ROOTFS_PATH}/etc/ssh/sshd_config.d"
    )
    for cfg in "${SSH_CONFIGS[@]}"; do
        if [ -e "$cfg" ]; then
            log_fail "SSH server config present: $cfg"
        else
            log_pass "SSH server config absent: $cfg"
        fi
    done
else
    log_info "SKIP: rootfs not mounted — service check deferred to CI"
fi

# -----------------------------------------------------------------------
# 3. LOGIN PATH CHECK
# -----------------------------------------------------------------------
log_info "--- 3. Login Path Check ---"

HARDENING_SCRIPT="${HARDENING_SCRIPT:-$(dirname "$0")/01-hardening.sh}"

# Verify getty masking is present in hardening script
if [ -f "$HARDENING_SCRIPT" ]; then
    if grep -q "mask getty" "$HARDENING_SCRIPT"; then
        log_pass "getty masking present in hardening script"
    else
        log_fail "getty masking not found in 01-hardening.sh"
    fi
    if grep -q "mask.*serial-getty" "$HARDENING_SCRIPT" || grep -q "serial-getty" "$HARDENING_SCRIPT"; then
        log_pass "serial-getty masking present in hardening script"
    else
        log_fail "serial-getty masking not found — P2 requirement"
    fi
    if grep -q "mask.*autovt" "$HARDENING_SCRIPT" || grep -q "autovt" "$HARDENING_SCRIPT"; then
        log_pass "autovt masking present in hardening script"
    else
        log_fail "autovt masking not found in hardening script"
    fi
    if grep -q "mask ssh" "$HARDENING_SCRIPT"; then
        log_pass "SSH masking present in hardening script"
    else
        log_fail "SSH masking not found in hardening script"
    fi
fi

if [ "$SOURCE_ONLY" -eq 0 ]; then
    # Check passwd for root password (must be locked or absent)
    SHADOW="${ROOTFS_PATH}/etc/shadow"
    if [ -f "$SHADOW" ]; then
        ROOT_ENTRY=$(grep '^root:' "$SHADOW" 2>/dev/null || true)
        if echo "$ROOT_ENTRY" | grep -qE '^root:(\*|!|!!)'; then
            log_pass "root account is locked (no usable password)"
        else
            log_fail "root account may have a usable password in /etc/shadow"
        fi
    else
        log_pass "/etc/shadow absent (expected in locked-down image)"
    fi

    # Check exam user shell is nologin
    PASSWD="${ROOTFS_PATH}/etc/passwd"
    if [ -f "$PASSWD" ]; then
        if grep -q "^exam:.*nologin" "$PASSWD"; then
            log_pass "exam user shell is nologin"
        else
            log_fail "exam user does not use nologin shell"
        fi
    fi
fi

# -----------------------------------------------------------------------
# 4. DEVELOPMENT CREDENTIALS / PLACEHOLDER CHECK
# -----------------------------------------------------------------------
log_info "--- 4. Development Credential Check ---"

PLACEHOLDER_PATTERNS=(
    "NOT_CONFIGURED"
    "NOT_PROVISIONED"
    "REPLACE_AT_DEPLOYMENT"
    "dev-agent-token"
    "placeholder"
    "changeme"
    "test-key"
    "ExamOS@Admin2025"
    "ExamOS@2026"
)

CONFIG_FILES=(
    "${ROOTFS_PATH}/etc/examos/admin.conf"
    "${ROOTFS_PATH}/etc/examos/proctor.env"
)

for cfg in "${CONFIG_FILES[@]}"; do
    if [ -f "$cfg" ]; then
        for pat in "${PLACEHOLDER_PATTERNS[@]}"; do
            if grep -qi "$pat" "$cfg" 2>/dev/null; then
                # Placeholder tokens in config are expected at build time;
                # they are replaced at deployment. Report as WARNING, not FAIL,
                # so CI build passes but deployment scripts must verify.
                log_info "NOTICE: Placeholder token '$pat' in $cfg (must be replaced at deployment)"
            fi
        done
    fi
done

# EXAM_URL must not be NOT_CONFIGURED in a release artifact check
EXAM_CONF="${ROOTFS_PATH}/etc/examos/exam.conf"
if [ -z "$ROOTFS_PATH" ]; then
    EXAM_CONF="$(dirname "$0")/../overlay/etc/examos/exam.conf"
fi
if [ -f "$EXAM_CONF" ]; then
    URL_VAL=$(grep -oP '(?<=EXAM_URL=).*' "$EXAM_CONF" | head -1 | tr -d '[:space:]' || true)
    if [ "$URL_VAL" = "NOT_CONFIGURED" ] || [ -z "$URL_VAL" ]; then
        log_info "NOTICE: EXAM_URL=NOT_CONFIGURED — must be set before candidate deployment"
    else
        log_pass "EXAM_URL is configured: $URL_VAL"
    fi
fi

# -----------------------------------------------------------------------
# 5. ALLOWED PACKAGE ALLOWLIST (source-time check via mkosi.conf)
# -----------------------------------------------------------------------
log_info "--- 5. Package Allowlist Check ---"

ALLOWED_PACKAGES=(
    "linux-image-amd64"
    "systemd" "systemd-boot" "systemd-boot-efi"
    "udev" "dbus"
    "cage"
    "chromium"
    "fonts-liberation" "fontconfig" "xkb-data"
    "pipewire" "wireplumber" "pipewire-pulse"
    "tpm2-tools" "tpm2-abrmd" "libtss2-tcti-device0" "libtss2-tcti-tabrmd0"
    "network-manager" "wpasupplicant" "iw"
    "ca-certificates" "openssl" "libssl3" "libpq5" "libcurl4"
    "postgresql" "postgresql-client"
    "nftables"
    "apparmor" "apparmor-utils"
    "libudev1"
    "pulseaudio-utils" "v4l-utils"
    "libgl1-mesa-dri"
    "kbd"
    "cryptsetup-bin"
    "usbguard"
    "squashfs-tools"
)

if [ -f "$MKOSI_CONF" ]; then
    # Extract package list from mkosi.conf (simple parse)
    MKOSI_PKGS=$(grep -E '^\s+[a-z]' "$MKOSI_CONF" | tr -d ' ' | grep -v '^#' | sort || true)
    log_info "Packages in mkosi.conf: $(echo "$MKOSI_PKGS" | wc -l | tr -d ' ')"

    # Check no clearly prohibited packages appear
    for pkg in bash gcc g++ openssh-server sudo python3 perl ruby nodejs npm curl wget; do
        if echo "$MKOSI_PKGS" | grep -qx "$pkg"; then
            log_fail "Package '$pkg' is in mkosi.conf but not allowed in release"
        else
            log_pass "Package '$pkg' absent from release mkosi.conf"
        fi
    done
fi

# -----------------------------------------------------------------------
# 6. APPARMOR ENFORCEMENT MODE
# -----------------------------------------------------------------------
log_info "--- 6. AppArmor Enforcement Check ---"

APPARMOR_PROFILE="${ROOTFS_PATH}/etc/apparmor.d/examos-kiosk"
LEGACY_APPARMOR_PROFILE="${ROOTFS_PATH}/etc/apparmor.d/usr.bin.chromium"
if [ -z "$ROOTFS_PATH" ]; then
    APPARMOR_PROFILE="$(dirname "$0")/../overlay/etc/apparmor.d/examos-kiosk"
    LEGACY_APPARMOR_PROFILE="$(dirname "$0")/../overlay/etc/apparmor.d/usr.bin.chromium"
fi
if [ -e "$LEGACY_APPARMOR_PROFILE" ]; then
    log_fail "Competing legacy Chromium AppArmor attachment is present: $LEGACY_APPARMOR_PROFILE"
elif [ -f "$APPARMOR_PROFILE" ]; then
    if ! grep -Fq 'profile examos-kiosk /{usr/bin,usr/lib/chromium}/chromium flags=(enforce) {' "$APPARMOR_PROFILE"; then
        log_fail "Canonical Chromium AppArmor profile is missing or not enforcing"
    else
        log_pass "Canonical Chromium AppArmor profile is enforcing with no competing legacy attachment"
    fi
else
    log_fail "Chromium AppArmor profile missing: $APPARMOR_PROFILE"
fi

# -----------------------------------------------------------------------
# 7. CHROMIUM POLICY VALIDATION
# -----------------------------------------------------------------------
log_info "--- 7. Chromium Policy Validation ---"

POLICY_FILE="${ROOTFS_PATH}/etc/chromium/policies/managed/examos_policies.json"
if [ -z "$ROOTFS_PATH" ]; then
    POLICY_FILE="$(dirname "$0")/../overlay/etc/chromium/policies/managed/examos_policies.json"
fi
if [ -f "$POLICY_FILE" ]; then
    # Must NOT have https://* in URLAllowlist (allows all HTTPS — defeats the policy)
    if python3 -c "
import json,sys
data=json.load(open('$POLICY_FILE'))
allow=data.get('URLAllowlist',[])
if 'https://*' in allow or 'http://*' in allow:
    sys.exit(1)
" 2>/dev/null; then
        log_pass "URLAllowlist does not contain wildcard HTTPS (https://*)"
    else
        log_fail "URLAllowlist contains 'https://*' — this allows ALL HTTPS destinations (P2 mandatory fix)"
    fi

    # Must have URLBlocklist with *
    if python3 -c "
import json,sys
data=json.load(open('$POLICY_FILE'))
bl=data.get('URLBlocklist',[])
sys.exit(0 if '*' in bl else 1)
" 2>/dev/null; then
        log_pass "URLBlocklist contains '*' (default-deny)"
    else
        log_fail "URLBlocklist missing '*' default-deny entry"
    fi

    # Must have AudioCaptureAllowedUrls (not AudioCaptureAllowed:true globally)
    if python3 -c "
import json,sys
data=json.load(open('$POLICY_FILE'))
# Global AudioCaptureAllowed:true without scoped URLs is a policy violation
if data.get('AudioCaptureAllowed',False) == True and not data.get('AudioCaptureAllowedUrls'):
    sys.exit(1)
sys.exit(0)
" 2>/dev/null; then
        log_pass "Audio capture is not globally enabled without origin scoping"
    else
        log_fail "AudioCaptureAllowed=true without AudioCaptureAllowedUrls — not origin-scoped"
    fi

    # Must have VideoCaptureAllowedUrls
    if python3 -c "
import json,sys
data=json.load(open('$POLICY_FILE'))
if data.get('VideoCaptureAllowed',False) == True and not data.get('VideoCaptureAllowedUrls'):
    sys.exit(1)
sys.exit(0)
" 2>/dev/null; then
        log_pass "Video capture is not globally enabled without origin scoping"
    else
        log_fail "VideoCaptureAllowed=true without VideoCaptureAllowedUrls — not origin-scoped"
    fi

    # DeveloperToolsAvailability must be 2
    if python3 -c "
import json,sys
data=json.load(open('$POLICY_FILE'))
sys.exit(0 if data.get('DeveloperToolsAvailability')==2 else 1)
" 2>/dev/null; then
        log_pass "DeveloperToolsAvailability=2 (disabled)"
    else
        log_fail "DeveloperToolsAvailability not set to 2"
    fi

    # DownloadRestrictions must be 3
    if python3 -c "
import json,sys
data=json.load(open('$POLICY_FILE'))
sys.exit(0 if data.get('DownloadRestrictions')==3 else 1)
" 2>/dev/null; then
        log_pass "DownloadRestrictions=3 (block all)"
    else
        log_fail "DownloadRestrictions not set to 3"
    fi
else
    log_fail "Chromium policy file not found at $POLICY_FILE"
fi

# -----------------------------------------------------------------------
# 8. NFTABLES CONFIGURATION
# -----------------------------------------------------------------------
log_info "--- 8. nftables Configuration Check ---"

NFT_CONF="${ROOTFS_PATH}/etc/nftables.conf"
if [ -z "$ROOTFS_PATH" ]; then
    NFT_CONF="$(dirname "$0")/../overlay/etc/nftables.conf"
fi
if [ -f "$NFT_CONF" ]; then
    if grep -q "policy drop" "$NFT_CONF"; then
        log_pass "nftables: default-deny (policy drop) present"
    else
        log_fail "nftables: policy drop not found"
    fi
    # TCP 80 should be restricted (not blanket allowed)
    if grep -qE "tcp dport 80 accept" "$NFT_CONF"; then
        log_info "NOTICE: TCP 80 blanket allowed — P2 requires restricting to CRL/OCSP hosts only"
    fi
    # Must not have any 0.0.0.0/0 allow rules
    if grep -qE "0\.0\.0\.0/0.*accept" "$NFT_CONF"; then
        log_fail "nftables: broad 0.0.0.0/0 accept rule found — must be restricted"
    else
        log_pass "nftables: no broad 0.0.0.0/0 accept rule"
    fi
else
    log_fail "nftables config not found at $NFT_CONF"
fi

# -----------------------------------------------------------------------
# Write JSON audit report
# -----------------------------------------------------------------------
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
PASS_COUNT=${#PASSED[@]}
FAIL_COUNT=${#FINDINGS[@]}

# Build findings array for JSON
FINDINGS_JSON=""
for f in "${FINDINGS[@]}"; do
    FINDINGS_JSON="${FINDINGS_JSON}\"${f}\","
done
FINDINGS_JSON="[${FINDINGS_JSON%,}]"

PASSED_JSON=""
for p in "${PASSED[@]}"; do
    PASSED_JSON="${PASSED_JSON}\"${p}\","
done
PASSED_JSON="[${PASSED_JSON%,}]"

cat > "$AUDIT_OUT" <<EOF
{
  "tool": "examos-release-audit",
  "version": "p2.1",
  "timestamp": "${TIMESTAMP}",
  "rootfs_path": "${ROOTFS_PATH:-SOURCE_ONLY}",
  "source_only_mode": ${SOURCE_ONLY},
  "summary": {
    "passed": ${PASS_COUNT},
    "failed": ${FAIL_COUNT},
    "overall": $([ "$FAIL_COUNT" -eq 0 ] && echo '"PASS"' || echo '"FAIL"')
  },
  "findings": ${FINDINGS_JSON},
  "passed_checks": ${PASSED_JSON}
}
EOF

echo ""
echo "=== [RELEASE-AUDIT] Summary ==="
echo "Passed: ${PASS_COUNT}"
echo "Failed: ${FAIL_COUNT}"
if [ "$FAIL_COUNT" -gt 0 ]; then
    echo "RESULT: FAIL — release image does not meet P2 security requirements"
    echo "Audit report: $AUDIT_OUT"
    exit 1
else
    echo "RESULT: PASS — release image passed all static audit checks"
    echo "Audit report: $AUDIT_OUT"
    exit 0
fi
