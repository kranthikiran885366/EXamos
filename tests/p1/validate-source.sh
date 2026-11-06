#!/usr/bin/env bash
# =============================================================================
# ExamOS P1 Source Validation — pre-build integrity check per spec §37.
# Verifies: files exist, config syntax, service paths, URL syntax, no secrets.
# =============================================================================
set -uo pipefail

WORKSPACE=$(cd "$(dirname "$0")/../.." && pwd)
FAILED=0
BLOCKED=0

echo "=== [P1-VALIDATE] Pre-Build Source Validation ==="

fail() { echo "[FAIL] $1"; FAILED=$((FAILED + 1)); }
pass() { echo "[PASS] $1"; }
blocked() { echo "[BLOCKED] $1"; BLOCKED=$((BLOCKED + 1)); }

# ── Required source files ─────────────────────────────────────────────────────
REQUIRED_FILES=(
    "image/mkosi.conf"
    "image/overlay/etc/examos/exam.conf"
    "image/overlay/etc/systemd/system/examos-kiosk.service"
    "image/overlay/etc/systemd/system/examos-agent.service"
    "image/overlay/etc/systemd/system/examos-server.service"
    "image/overlay/etc/systemd/system/examos-preflight.service"
    "image/overlay/etc/systemd/system/examos-dev-shm-hardening.service"
    "image/overlay/etc/systemd/system/examos-kiosk-readiness.service"
    "image/overlay/usr/local/bin/examos-kiosk-readiness"
    "image/overlay/etc/apparmor.d/examos-kiosk"
    "image/scripts/p2-startup-validator.sh"
    "image/overlay/usr/lib/sysusers.d/examos.conf"
    "image/overlay/etc/apparmor.d/usr.bin.chromium"
    "image/overlay/etc/chromium/policies/managed/examos_policies.json"
    "image/overlay/etc/nftables.conf"
    "image/overlay/etc/sysctl.d/99-examos-security.conf"
    "image/overlay/etc/udev/rules.d/99-examos-usb-lockdown.rules"
    "kiosk/launcher/launcher.c"
    "kiosk/launcher/Makefile"
    "agent/main.c"
    "server/main.c"
    "Makefile"
)
for f in "${REQUIRED_FILES[@]}"; do
    [ -f "$WORKSPACE/$f" ] && pass "file exists: $f" || fail "file missing: $f"
done

KIOSK_LINK="$WORKSPACE/image/overlay/etc/systemd/system/graphical.target.wants/examos-kiosk.service"
KIOSK_LINK_TARGET=$(readlink "$KIOSK_LINK" 2>/dev/null || true)
KIOSK_LINK_POINTER=$(tr -d '\r\n' < "$KIOSK_LINK" 2>/dev/null || true)
if [ "$KIOSK_LINK_TARGET" = "/etc/systemd/system/examos-kiosk.service" ] || \
   [ "$KIOSK_LINK_TARGET" = "../examos-kiosk.service" ]; then
    pass "kiosk target symlink points to examos-kiosk.service"
elif [ "$KIOSK_LINK_POINTER" = "/etc/systemd/system/examos-kiosk.service" ] && \
     grep -Fq 'enable_required_unit examos-kiosk.service' "$WORKSPACE/image/scripts/03-p2-lockdown.sh" 2>/dev/null; then
    # A Windows checkout cannot retain this Unix symlink.  The P2 image-build
    # script creates it with systemctl inside BUILDROOT; an image/boot gate
    # must still verify the materialized link before release.
    pass "kiosk enablement is materialized inside BUILDROOT during image build"
else
    fail "kiosk target link/pointer or BUILDROOT materializer is invalid"
fi

# ── mkosi.conf syntax ─────────────────────────────────────────────────────────
MKOSI="$WORKSPACE/image/mkosi.conf"
grep -q "^\[Distribution\]" "$MKOSI" 2>/dev/null && pass "mkosi.conf: [Distribution] section" || fail "mkosi.conf: missing [Distribution] section"
grep -q "^\[Content\]"      "$MKOSI" 2>/dev/null && pass "mkosi.conf: [Content] section"      || fail "mkosi.conf: missing [Content] section"
grep -q "^Bootable=yes"     "$MKOSI" 2>/dev/null && pass "mkosi.conf: Bootable=yes"           || fail "mkosi.conf: Bootable=yes missing"
grep -Fq "PostInstallationScripts=scripts/03-p2-lockdown.sh" "$MKOSI" 2>/dev/null \
    && pass "mkosi.conf: P2 lockdown post-install script enabled" \
    || fail "mkosi.conf: P2 lockdown post-install script missing"

# ── AppArmor profile syntax ──────────────────────────────────────────────────
APPARMOR_PARSER=$(command -v apparmor_parser 2>/dev/null || true)
if [ -z "$APPARMOR_PARSER" ]; then
    blocked "apparmor_parser is unavailable; cannot validate kiosk confinement profiles"
else
    for profile in \
        "$WORKSPACE/image/overlay/etc/apparmor.d/examos-kiosk" \
        "$WORKSPACE/image/overlay/etc/apparmor.d/usr.bin.chromium"; do
        if "$APPARMOR_PARSER" -Q "$profile" >/dev/null 2>&1; then
            pass "AppArmor profile syntax valid: ${profile##*/}"
        else
            fail "AppArmor profile syntax invalid: ${profile##*/}"
        fi
    done
fi

# ── kiosk service: User=exam (not root) ───────────────────────────────────────
KIOSK_SVC="$WORKSPACE/image/overlay/etc/systemd/system/examos-kiosk.service"
tr -d '\r' < "$KIOSK_SVC" 2>/dev/null | grep -q "^User=exam$" && pass "kiosk service: User=exam" || fail "kiosk service: User must be exam, not root"
tr -d '\r' < "$KIOSK_SVC" 2>/dev/null | grep -q "^ExecStart=.*cage" && pass "kiosk service: ExecStart references cage" || fail "kiosk service: ExecStart must reference cage"
grep -q "examos-kiosk-launcher" "$KIOSK_SVC" 2>/dev/null && pass "kiosk service: references examos-kiosk-launcher" || fail "kiosk service: missing examos-kiosk-launcher reference"

# ── launcher.c: no sandbox-disabling flags ────────────────────────────────────
LAUNCHER_C="$WORKSPACE/kiosk/launcher/launcher.c"
! grep -q "\-\-no-sandbox"         "$LAUNCHER_C" 2>/dev/null && pass "launcher.c: no --no-sandbox"         || fail "launcher.c: --no-sandbox must be removed"
! grep -q "\-\-disable-gpu-sandbox" "$LAUNCHER_C" 2>/dev/null && pass "launcher.c: no --disable-gpu-sandbox" || fail "launcher.c: --disable-gpu-sandbox must be removed"
! grep -q "\-\-test-type"           "$LAUNCHER_C" 2>/dev/null && pass "launcher.c: no --test-type"          || fail "launcher.c: --test-type must be removed"
! grep -q "127\.0\.0\.1:8000"       "$LAUNCHER_C" 2>/dev/null && pass "launcher.c: no hardcoded fallback URL" || fail "launcher.c: hardcoded fallback URL must be removed"

# ── exam.conf URL syntax ──────────────────────────────────────────────────────
EXAM_CONF="$WORKSPACE/image/overlay/etc/examos/exam.conf"
URL_VAL=$(grep -oP '(?<=EXAM_URL=).*' "$EXAM_CONF" 2>/dev/null | head -1 | tr -d '[:space:]')
if [ -z "$URL_VAL" ]; then
    fail "exam.conf: EXAM_URL key missing"
elif [ "$URL_VAL" = "NOT_CONFIGURED" ]; then
    blocked "exam.conf: EXAM_URL=NOT_CONFIGURED — set a real staging URL before P1 gate"
elif [[ "$URL_VAL" == http://* ]] || [[ "$URL_VAL" == https://* ]]; then
    pass "exam.conf: EXAM_URL syntax valid ($URL_VAL)"
else
    fail "exam.conf: EXAM_URL must start with http:// or https://"
fi

# ── sysusers: exam user ───────────────────────────────────────────────────────
SYSUSERS="$WORKSPACE/image/overlay/usr/lib/sysusers.d/examos.conf"
grep -q "^u exam 1000" "$SYSUSERS" 2>/dev/null && pass "sysusers: exam UID=1000" || fail "sysusers: exam UID=1000 missing"
grep -q "nologin" "$SYSUSERS" 2>/dev/null && pass "sysusers: exam nologin shell" || fail "sysusers: exam must have nologin shell"

# ── No production secrets ─────────────────────────────────────────────────────
SECRET_FINDINGS=$(find "$WORKSPACE" \
    \( -path "$WORKSPACE/.git" -o -path "$WORKSPACE/artifacts" \
       -o -path "$WORKSPACE/build" -o -path "$WORKSPACE/cache" \
       -o -path "$WORKSPACE/output" -o -path "$WORKSPACE/image/trust" \) -prune -o \
    -type f \( -name "*.pem" -o -name "*.key" -o -name "*.pfx" -o -name "*.p12" \
       -o -name "id_rsa" -o -name "id_ed25519" \) -print 2>/dev/null || true)
[ -z "$SECRET_FINDINGS" ] && pass "no production secrets committed" || { fail "production secrets found: $SECRET_FINDINGS"; }

# ── admin.conf: no plaintext password in comment ──────────────────────────────
ADMIN_CONF="$WORKSPACE/image/overlay/etc/examos/admin.conf"
[ -f "$ADMIN_CONF" ] && ! grep -q "ExamOS@Admin" "$ADMIN_CONF" 2>/dev/null \
    && pass "admin.conf: no plaintext password" || fail "admin.conf: plaintext password must be removed"

# ── candidates.conf: no real candidate records ────────────────────────────────
CAND_CONF="$WORKSPACE/image/overlay/etc/examos/candidates.conf"
[ -f "$CAND_CONF" ] && ! grep -qE "^CAND-[0-9]" "$CAND_CONF" 2>/dev/null \
    && pass "candidates.conf: no real candidate records" || fail "candidates.conf: real candidate records must be removed"

# ── server/main.c: no hardcoded phase/version strings ────────────────────────
SERVER_MAIN="$WORKSPACE/server/main.c"
! grep -q '"phase":"P4"'                "$SERVER_MAIN" 2>/dev/null && pass "server/main.c: no hardcoded phase P4"          || fail "server/main.c: hardcoded phase P4 must be fixed"
! grep -q '"appliance_version":"0.4.0"' "$SERVER_MAIN" 2>/dev/null && pass "server/main.c: no hardcoded version 0.4.0"     || fail "server/main.c: hardcoded version 0.4.0 must be fixed"

# ── exam_engine.c: no hardcoded secret in submission hash ────────────────────
EXAM_ENGINE="$WORKSPACE/server/exam/exam_engine.c"
! grep -q "ExamOS_Master_Vault" "$EXAM_ENGINE" 2>/dev/null && pass "exam_engine.c: no hardcoded secret in hash" || fail "exam_engine.c: hardcoded secret in submission hash must be removed"

# ── launcher.sh: no dead Python reference ────────────────────────────────────
LAUNCHER_SH="$WORKSPACE/kiosk/launcher/launcher.sh"
! grep -q "launcher.py" "$LAUNCHER_SH" 2>/dev/null && pass "launcher.sh: no dead Python reference" || fail "launcher.sh: dead Python reference must be removed"

echo ""
echo "=== [P1-VALIDATE] Summary ==="
if [ "$FAILED" -eq 0 ]; then
    if [ "$BLOCKED" -eq 0 ]; then
        echo "[P1-VALIDATE] PASS: All source validation checks passed"
        exit 0
    fi
    echo "[P1-VALIDATE] BLOCKED: $BLOCKED prerequisite(s) are unavailable"
    exit 2
else
    echo "[P1-VALIDATE] FAIL: $FAILED check(s) failed — fix before building"
    exit 1
fi
