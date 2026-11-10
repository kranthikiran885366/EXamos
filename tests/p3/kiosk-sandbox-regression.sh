#!/usr/bin/env bash
# =============================================================================
# ExamOS kiosk sandbox regression checks
#
# Static regression guard for the Chromium kiosk sandbox. The dynamic proof is
# still the QEMU boot gate (VH-02/VH-04); this test prevents the configuration
# regressions that made the guest kiosk fail to start:
#   - an invalid AppArmor capability rule (`capability ptrace`)
#   - a capability bounding set that removes the capabilities Chromium needs
#     inside its own user namespace
#   - the AppArmor unprivileged-userns sysctl being absent
#   - readiness accepting a Chromium process that only survives a few seconds
# =============================================================================
set -euo pipefail

WORKSPACE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
UNIT="$WORKSPACE/image/overlay/etc/systemd/system/examos-kiosk.service"
PROFILE="$WORKSPACE/image/overlay/etc/apparmor.d/examos-kiosk"
SYSCTL="$WORKSPACE/image/overlay/etc/sysctl.d/99-examos-security.conf"
READINESS="$WORKSPACE/image/overlay/usr/local/bin/examos-kiosk-readiness"
QEMU_TEST="$WORKSPACE/tests/virtual-hardware/tests/qemu-boot.sh"

fail=0
check_file() {
    local path="$1"
    if [[ ! -s "$path" ]]; then
        printf '[KIOSK-REGRESSION] FAIL: required file is missing or empty: %s\n' "$path" >&2
        fail=1
    fi
}
check_line() {
    local path="$1" line="$2" description="$3"
    if ! grep -Fxq -- "$line" "$path"; then
        printf '[KIOSK-REGRESSION] FAIL: %s (missing exact line in %s)\n' \
            "$description" "${path#"$WORKSPACE"/}" >&2
        fail=1
    fi
}
check_absent() {
    local path="$1" pattern="$2" description="$3"
    if grep -Fq -- "$pattern" "$path"; then
        printf '[KIOSK-REGRESSION] FAIL: %s (found %s in %s)\n' \
            "$description" "$pattern" "${path#"$WORKSPACE"/}" >&2
        fail=1
    fi
}
check_contains() {
    local path="$1" pattern="$2" description="$3"
    if ! grep -Fq -- "$pattern" "$path"; then
        printf '[KIOSK-REGRESSION] FAIL: %s (missing %s in %s)\n' \
            "$description" "$pattern" "${path#"$WORKSPACE"/}" >&2
        fail=1
    fi
}

for path in "$UNIT" "$PROFILE" "$SYSCTL" "$READINESS" "$QEMU_TEST"; do
    check_file "$path"
done

# Kiosk service: unprivileged user, mandatory hardening, and a capability
# bounding set that still permits Chromium's user-namespace sandbox setup.
check_line "$UNIT" 'User=exam' 'kiosk must run as the unprivileged exam user'
check_line "$UNIT" 'Group=exam' 'kiosk must run in the exam group'
check_line "$UNIT" 'NoNewPrivileges=true' 'kiosk must set NoNewPrivileges'
check_line "$UNIT" 'ProtectSystem=strict' 'kiosk must set ProtectSystem=strict'
check_line "$UNIT" 'ProtectHome=true' 'kiosk must set ProtectHome'
check_line "$UNIT" 'PrivateTmp=true' 'kiosk must set PrivateTmp'
check_line "$UNIT" 'LockPersonality=true' 'kiosk must set LockPersonality'
check_line "$UNIT" 'Requires=examos-preflight.service' 'kiosk must not start when mandatory preflight fails'
check_line "$UNIT" 'After=examos-preflight.service' 'kiosk must wait for mandatory preflight'
check_absent "$UNIT" 'User=root' 'kiosk must not run as root'
check_absent "$UNIT" '--no-sandbox' 'kiosk must not disable the Chromium sandbox'
unit_caps="$(grep -E '^CapabilityBoundingSet=' "$UNIT" || true)"
for cap in CAP_SYS_ADMIN CAP_SETUID CAP_SETGID CAP_SYS_CHROOT; do
    if [[ "$unit_caps" != *"$cap"* ]]; then
        printf '[KIOSK-REGRESSION] FAIL: CapabilityBoundingSet must include %s for the Chromium user namespace sandbox\n' "$cap" >&2
        fail=1
    fi
done

# AppArmor profile: attach to the real Chromium binary, allow userns and the
# capabilities Chromium needs, and never use the parser-invalid `ptrace` name.
check_line "$PROFILE" 'profile examos-kiosk /{usr/bin,usr/lib/chromium}/chromium flags=(enforce) {' \
    'AppArmor profile must attach to both Chromium paths'
check_contains "$PROFILE" 'userns,' 'AppArmor profile must allow unprivileged user namespaces'
check_contains "$PROFILE" 'capability sys_admin,' 'AppArmor profile must allow sys_admin inside the userns'
check_contains "$PROFILE" '/usr/lib/chromium/chromium Px -> examos-kiosk,' \
    'AppArmor profile must transition the real Chromium binary'
check_absent "$PROFILE" 'capability ptrace,' 'AppArmor profile must not use the invalid ptrace capability token'
check_absent "$PROFILE" 'deny capability sys_admin,' 'AppArmor profile must not deny sys_admin inside the userns'

# Kernel settings: Debian's AppArmor userns restriction must not block the
# Chromium sandbox.
check_line "$SYSCTL" 'kernel.unprivileged_userns_clone = 1' \
    'unprivileged user namespaces must be enabled'
check_line "$SYSCTL" 'kernel.apparmor_restrict_unprivileged_userns = 0' \
    'AppArmor must not restrict unprivileged user namespaces'

# Readiness: require the same Chromium PID for a stable interval, not just any
# matching process at one instant.
check_contains "$READINESS" 'stable_seconds=10' 'readiness must require a 10 second stable interval'
check_contains "$READINESS" 'chromium_pid=' 'readiness must report the stable Chromium PID'
check_contains "$READINESS" 'kill -0 "$chromium_pid"' 'readiness must verify the Chromium PID is alive'
check_contains "$READINESS" 'EXAMOS_KIOSK_READY cage=1 chromium=1 wayland_socket=1' \
    'readiness must emit the canonical READY marker'
check_contains "$READINESS" 'EXAMOS_KIOSK_DIAGNOSTICS_COMPLETE' \
    'readiness must emit diagnostics on failure'
check_absent "$READINESS" '/run/user/1000' \
    'readiness must not assume the interactive user runtime directory'

# Boot gate: the stability interval must reject a Chromium that exits or logs
# an unusable sandbox after readiness was reported.
check_contains "$QEMU_TEST" 'No usable sandbox' 'QEMU gate must reject an unusable Chromium sandbox'
check_contains "$QEMU_TEST" 'Chromium exited' 'QEMU gate must reject Chromium exits during stability'
check_contains "$QEMU_TEST" 'stable_seconds=10' 'QEMU gate must require the strengthened readiness marker'
check_contains "$QEMU_TEST" 'mandatory startup preflight or USBGuard failed' \
    'QEMU gate must reject a boot with failed mandatory controls'
check_contains "$QEMU_TEST" 'guest TPM device, TPM resource manager, or attestation agent failed' \
    'QEMU gate must reject a boot without guest TPM and attestation services'

if [[ "$fail" -ne 0 ]]; then
    printf '[KIOSK-REGRESSION] FAIL: kiosk sandbox regression checks failed.\n' >&2
    exit 1
fi

printf '[KIOSK-REGRESSION] PASS: kiosk sandbox configuration, AppArmor userns policy, readiness stability, and boot-gate checks are consistent.\n'
