#!/usr/bin/env bash
# =============================================================================
# ExamOS P1 Doctor — verifies every P1 build and runtime requirement.
# Extends P0 doctor. All checks are dynamic — no hardcoded PASS values.
# =============================================================================
set -uo pipefail

WORKSPACE=$(cd "$(dirname "$0")/../.." && pwd)
FAILED=0
BLOCKED=0

echo "========================================"
echo "          EXAMOS P1 DOCTOR"
echo "========================================"

chk() {
    local name="$1" result="$2"
    printf "%-45s %s\n" "$name" "$result"
    if [ "$result" = "FAIL" ]; then
        FAILED=$((FAILED + 1))
    elif [ "$result" = "BLOCKED" ]; then
        BLOCKED=$((BLOCKED + 1))
    fi
    # Call sites deliberately use `condition && chk PASS || chk FAIL`.
    # Always return success so a recorded PASS cannot be reclassified as FAIL.
    return 0
}

# ── mkosi configuration ──────────────────────────────────────────────────────
MKOSI="$WORKSPACE/image/mkosi.conf"
[ -f "$MKOSI" ] && chk "mkosi.conf exists"                  "PASS" || chk "mkosi.conf exists" "FAIL"
grep -q "Distribution=debian"  "$MKOSI" 2>/dev/null && \
grep -q "Release=trixie"       "$MKOSI" 2>/dev/null && \
grep -q "Architecture=x86-64"  "$MKOSI" 2>/dev/null \
    && chk "mkosi: Debian Trixie x86-64"                    "PASS" || chk "mkosi: Debian Trixie x86-64" "FAIL"

for pkg in cage chromium linux-image-amd64 systemd ca-certificates \
           network-manager libgl1-mesa-dri fonts-liberation; do
    grep -q "$pkg" "$MKOSI" 2>/dev/null \
        && chk "mkosi package: $pkg"                        "PASS" || chk "mkosi package: $pkg" "FAIL"
done

for de in gnome kde xfce lightdm gdm3 lxde mate cinnamon; do
    ! grep -qiE "^\s*${de}(\s|$)" "$MKOSI" 2>/dev/null \
        && chk "No DE in mkosi: $de"                        "PASS" || chk "No DE in mkosi: $de" "FAIL"
done

# ── Kiosk service ─────────────────────────────────────────────────────────────
KIOSK_SVC="$WORKSPACE/image/overlay/etc/systemd/system/examos-kiosk.service"
[ -f "$KIOSK_SVC" ]                                         && chk "examos-kiosk.service exists"        "PASS" || chk "examos-kiosk.service exists" "FAIL"
grep -q "^User=exam$"              "$KIOSK_SVC" 2>/dev/null && chk "kiosk service User=exam"            "PASS" || chk "kiosk service User=exam" "FAIL"
grep -q "WantedBy=graphical.target" "$KIOSK_SVC" 2>/dev/null && chk "kiosk WantedBy=graphical.target"  "PASS" || chk "kiosk WantedBy=graphical.target" "FAIL"
grep -q "XDG_RUNTIME_DIR=/run/user/1000" "$KIOSK_SVC" 2>/dev/null && chk "kiosk XDG_RUNTIME_DIR=1000" "PASS" || chk "kiosk XDG_RUNTIME_DIR=1000" "FAIL"
grep -q "Restart=on-failure"       "$KIOSK_SVC" 2>/dev/null && chk "kiosk Restart=on-failure"          "PASS" || chk "kiosk Restart=on-failure" "FAIL"

WANTS="$WORKSPACE/image/overlay/etc/systemd/system/graphical.target.wants/examos-kiosk.service"
WANTS_TARGET=$(readlink "$WANTS" 2>/dev/null || true)
WANTS_POINTER=$(tr -d '\r\n' < "$WANTS" 2>/dev/null || true)
if [ "$WANTS_TARGET" = "/etc/systemd/system/examos-kiosk.service" ] || \
   [ "$WANTS_TARGET" = "../examos-kiosk.service" ]; then
    chk "kiosk enablement source link" "PASS"
elif [ "$WANTS_POINTER" = "/etc/systemd/system/examos-kiosk.service" ] && \
     grep -Fq 'enable_required_unit examos-kiosk.service' "$WORKSPACE/image/scripts/03-p2-lockdown.sh" 2>/dev/null; then
    # NTFS/DrvFS may turn an overlay symlink into a text pointer.  The image
    # build recreates the real link in BUILDROOT; boot/image tests verify it.
    chk "kiosk enablement materialized in BUILDROOT" "PASS"
else
    chk "kiosk enablement source or materializer" "FAIL"
fi

# ── exam user ─────────────────────────────────────────────────────────────────
SYSUSERS="$WORKSPACE/image/overlay/usr/lib/sysusers.d/examos.conf"
[ -f "$SYSUSERS" ] && grep -q "^u exam 1000" "$SYSUSERS" 2>/dev/null \
    && chk "exam user sysusers UID=1000 nologin"            "PASS" || chk "exam user sysusers UID=1000 nologin" "FAIL"

# ── exam.conf ─────────────────────────────────────────────────────────────────
EXAM_CONF="$WORKSPACE/image/overlay/etc/examos/exam.conf"
[ -f "$EXAM_CONF" ]                                         && chk "/etc/examos/exam.conf exists"       "PASS" || chk "/etc/examos/exam.conf exists" "FAIL"
if [ -f "$EXAM_CONF" ]; then
    URL_VAL=$(grep -oP '(?<=EXAM_URL=).*' "$EXAM_CONF" 2>/dev/null | head -1 | tr -d '[:space:]')
    if [ "$URL_VAL" = "NOT_CONFIGURED" ]; then
        chk "EXAM_URL configured"                           "BLOCKED"
    elif [[ "$URL_VAL" == http://* ]] || [[ "$URL_VAL" == https://* ]]; then
        chk "EXAM_URL configured"                           "PASS"
    else
        chk "EXAM_URL configured"                           "FAIL"
    fi
fi

# ── Launcher binary & source ──────────────────────────────────────────────────
LAUNCHER_BIN="$WORKSPACE/kiosk/launcher/examos-kiosk-launcher"
LAUNCHER_C="$WORKSPACE/kiosk/launcher/launcher.c"
[ -f "$LAUNCHER_BIN" ] && [ -x "$LAUNCHER_BIN" ]           && chk "examos-kiosk-launcher binary"       "PASS" || chk "examos-kiosk-launcher binary (run make)" "FAIL"
[ -f "$LAUNCHER_C" ] && ! grep -q "\-\-no-sandbox"   "$LAUNCHER_C" 2>/dev/null && chk "launcher: no --no-sandbox"   "PASS" || chk "launcher: no --no-sandbox" "FAIL"
[ -f "$LAUNCHER_C" ] && ! grep -q "\-\-test-type"    "$LAUNCHER_C" 2>/dev/null && chk "launcher: no --test-type"    "PASS" || chk "launcher: no --test-type" "FAIL"
[ -f "$LAUNCHER_C" ] && ! grep -q "\-\-disable-gpu-sandbox" "$LAUNCHER_C" 2>/dev/null && chk "launcher: no --disable-gpu-sandbox" "PASS" || chk "launcher: no --disable-gpu-sandbox" "FAIL"
[ -f "$LAUNCHER_C" ] && ! grep -q "127.0.0.1:8000"  "$LAUNCHER_C" 2>/dev/null && chk "launcher: no hardcoded fallback URL" "PASS" || chk "launcher: no hardcoded fallback URL" "FAIL"

# ── Security overlays ─────────────────────────────────────────────────────────
[ -f "$WORKSPACE/image/overlay/etc/apparmor.d/usr.bin.chromium" ]                          && chk "AppArmor Chromium profile"          "PASS" || chk "AppArmor Chromium profile" "FAIL"
[ -f "$WORKSPACE/image/overlay/etc/chromium/policies/managed/examos_policies.json" ]       && chk "Chromium managed policies"          "PASS" || chk "Chromium managed policies" "FAIL"
[ -f "$WORKSPACE/image/overlay/etc/nftables.conf" ]                                        && chk "nftables.conf exists"               "PASS" || chk "nftables.conf exists" "FAIL"
[ -f "$WORKSPACE/image/overlay/etc/sysctl.d/99-examos-security.conf" ]                     && chk "sysctl hardening conf"              "PASS" || chk "sysctl hardening conf" "FAIL"
[ -f "$WORKSPACE/image/overlay/etc/udev/rules.d/99-examos-usb-lockdown.rules" ]            && chk "USB udev lockdown rules"            "PASS" || chk "USB udev lockdown rules" "FAIL"

# ── No production secrets ─────────────────────────────────────────────────────
SECRET_FINDINGS=$(find "$WORKSPACE" -type f \
    \( -name "*.pem" -o -name "*.key" -o -name "*.pfx" -o -name "*.p12" \
       -o -name "id_rsa" -o -name "id_ed25519" \) \
    ! -path "*/.git/*" ! -path "*/build/*" ! -path "*/image/trust/*" 2>/dev/null || true)
[ -z "$SECRET_FINDINGS" ]                                   && chk "No production secrets committed"   "PASS" || { chk "No production secrets committed" "FAIL"; echo "  Found: $SECRET_FINDINGS"; }

# ── admin.conf: no plaintext password in comment ──────────────────────────────
ADMIN_CONF="$WORKSPACE/image/overlay/etc/examos/admin.conf"
if [ -f "$ADMIN_CONF" ]; then
    ! grep -q "ExamOS@Admin" "$ADMIN_CONF" 2>/dev/null \
        && chk "admin.conf: no plaintext password"          "PASS" || chk "admin.conf: no plaintext password" "FAIL"
fi

# ── candidates.conf: no real candidate data ───────────────────────────────────
CAND_CONF="$WORKSPACE/image/overlay/etc/examos/candidates.conf"
if [ -f "$CAND_CONF" ]; then
    ! grep -qE "^CAND-[0-9]" "$CAND_CONF" 2>/dev/null \
        && chk "candidates.conf: no real candidate records"  "PASS" || chk "candidates.conf: no real candidate records" "FAIL"
fi

# ── server version strings ────────────────────────────────────────────────────
SERVER_MAIN="$WORKSPACE/server/main.c"
if [ -f "$SERVER_MAIN" ]; then
    ! grep -q '"phase":"P4"'           "$SERVER_MAIN" 2>/dev/null && chk "server: no hardcoded phase P4"          "PASS" || chk "server: no hardcoded phase P4" "FAIL"
    ! grep -q '"appliance_version":"0.4.0"' "$SERVER_MAIN" 2>/dev/null && chk "server: no hardcoded version 0.4.0" "PASS" || chk "server: no hardcoded version 0.4.0" "FAIL"
fi

# ── Host tools ────────────────────────────────────────────────────────────────
for tool in qemu-system-x86_64 swtpm mkosi gcc g++; do
    command -v "$tool" >/dev/null 2>&1 \
        && chk "tool: $tool"                                "PASS" || chk "tool: $tool" "FAIL"
done

OVMF_FOUND=0
for cand in "/usr/share/OVMF/OVMF_CODE_4M.fd" "/usr/share/OVMF/OVMF_CODE.fd" "/usr/share/ovmf/OVMF.fd"; do
    if [ -f "$cand" ]; then OVMF_FOUND=1; chk "OVMF firmware ($cand)" "PASS"; break; fi
done
[ "$OVMF_FOUND" -eq 0 ] && chk "OVMF firmware" "FAIL"

# ── Documentation ─────────────────────────────────────────────────────────────
for doc in \
    "docs/development/p1-overview.md" \
    "docs/development/p1-building.md" \
    "docs/development/p1-running.md" \
    "docs/development/p1-testing.md" \
    "docs/development/p1-troubleshooting.md" \
    "docs/testing/p1-gate.md"; do
    [ -f "$WORKSPACE/$doc" ] \
        && chk "doc: $doc"                                  "PASS" || chk "doc: $doc" "FAIL"
done

echo "========================================"
if [ "$FAILED" -eq 0 ] && [ "$BLOCKED" -eq 0 ]; then
    echo "EXAMOS P1 DOCTOR: PASS"
    exit 0
elif [ "$FAILED" -eq 0 ]; then
    echo "EXAMOS P1 DOCTOR: BLOCKED ($BLOCKED external prerequisite(s))"
    exit 2
else
    echo "EXAMOS P1 DOCTOR: $FAILED check(s) FAILED"
    exit 1
fi
