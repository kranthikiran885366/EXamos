#!/usr/bin/env bash
# =============================================================================
# ExamOS P2 Build Script — Lockdown Controls
# Runs INSIDE the mkosi chroot during image assembly.
#
# Sections:
#   A. OS identity
#   B. Login path removal  (§7)
#   C. SSH removal         (§7)
#   D. sudo/su removal     (§7)
#   E. Root account lock   (§7)
#   F. Swap disable        (§6)
#   G. Core dump disable   (§6)
#   H. AppArmor enforce    (§8)
#   I. nftables ordering   (§11)
#   J. USB default-deny    (§9)
#   K. Module lock service (§8)
#   L. Lockdown-fail guard (§23)
#   M. tmpfs mount enables (§5)
#   N. tmpfiles.d skeleton (§5)
#   O. Unnecessary service mask (§7)
#   P. P2 config file      (§15)
#   Q. Service symlinks    (all)
#
# The sysctl file (99-examos-security.conf) is a static overlay file and
# is NOT modified by this script to prevent duplicate key injection.
# =============================================================================
set -euo pipefail

BR="${BUILDROOT}"

echo "=== [ExamOS P2] Applying Phase 2 Lockdown Controls ==="

VALIDATOR="${BR}/usr/local/bin/p2-startup-validator.sh"
if [ ! -x "$VALIDATOR" ]; then
    echo "[P2] FAIL: production runtime validator is missing" >&2
    exit 1
fi
if ! grep -Fq 'EXPECTED_CHECKS=18' "$VALIDATOR" || \
   ! grep -Fq 'V-16-ROOTVERITY' "$VALIDATOR"; then
    echo "[P2] FAIL: incomplete runtime validator staged; use scripts/build-full-image.sh" >&2
    exit 1
fi

enable_required_unit() {
    local unit="$1"
    if ! systemctl --root="${BR}" enable "$unit"; then
        echo "[P2] FAIL: required systemd unit could not be enabled: ${unit}" >&2
        exit 1
    fi
}

# mkosi runs "systemctl preset-all" after this post-install script. A unit that
# has already been masked makes preset-all fail when a vendor preset still tries
# to enable it, which aborts the image build. Record the units to mask here,
# drop their enablement, and let the finalize script apply the actual mask
# symlinks after preset-all has completed.
MASK_LIST="${BR}/etc/examos/p2-mask.list"
mkdir -p "${BR}/etc/examos"
: > "$MASK_LIST"

defer_mask() {
    local unit
    for unit in "$@"; do
        [ -n "$unit" ] || continue
        printf '%s\n' "$unit" >> "$MASK_LIST"
        systemctl --root="${BR}" disable "$unit" 2>/dev/null || true
    done
}

# The overlay may already ship mask symlinks (for example getty@tty1..6). Those
# are applied before this script runs, and a mask for a unit with a
# DefaultInstance makes mkosi's later "systemctl preset-all" return failure.
# Fold every pre-existing mask into the deferred list and remove the symlink
# here; the finalize script re-applies it after preset-all has completed.
while IFS= read -r -d '' masked_link; do
    printf '%s\n' "${masked_link##*/}" >> "$MASK_LIST"
    rm -f -- "$masked_link"
done < <(find "${BR}/etc/systemd/system" -maxdepth 1 -type l -lname '/dev/null' -print0 2>/dev/null)

# ---------------------------------------------------------------------------
# A. OS identity
# ---------------------------------------------------------------------------
cat > "${BR}/etc/os-release" <<'OSEOF'
NAME="ExamOS"
PRETTY_NAME="ExamOS 0.3.0 (Phase 2 — Lockdown)"
ID=examos
ID_LIKE=debian
VERSION="0.3.0"
VERSION_ID="0.3.0"
BUILD_ID=p2
OSEOF
echo "[P2] A: os-release updated"

# ---------------------------------------------------------------------------
# B. Login path removal — mask every getty / autovt / serial / emergency path
# ---------------------------------------------------------------------------
for i in 1 2 3 4 5 6 7 8 9; do
    defer_mask "getty@tty${i}.service"
done
defer_mask "autovt@.service"
defer_mask "serial-getty@.service"
defer_mask "emergency.service"
defer_mask "emergency.target"
defer_mask "rescue.service"
defer_mask "rescue.target"
defer_mask "systemd-debug-shell.service"
echo "[P2] B: all getty/autovt/serial/emergency paths masked"

# ---------------------------------------------------------------------------
# C. SSH server — absent, masked, config removed
# ---------------------------------------------------------------------------
for svc in ssh sshd openssh-server openssh-daemon; do
    systemctl --root="${BR}" disable "${svc}.service" 2>/dev/null || true
    defer_mask "${svc}.service"
done
rm -f  "${BR}/etc/ssh/sshd_config"
rm -rf "${BR}/etc/ssh/sshd_config.d"
rm -f  "${BR}/usr/sbin/sshd"
echo "[P2] C: SSH server masked + config removed"

# ---------------------------------------------------------------------------
# D. sudo / su removal — binaries and config
# ---------------------------------------------------------------------------
for bin in sudo su newgrp pkexec; do
    for dir in /usr/bin /bin /usr/sbin /sbin; do
        [ -f "${BR}${dir}/${bin}" ] && rm -f "${BR}${dir}/${bin}" && \
            echo "[P2] D: removed ${dir}/${bin}"
    done
done
rm -rf "${BR}/etc/sudoers" "${BR}/etc/sudoers.d"
echo "[P2] D: sudo/su removed"

# ---------------------------------------------------------------------------
# E. Root account — locked, nologin shell, no password
# ---------------------------------------------------------------------------
sed -i 's|^\(root:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:\).*$|\1/usr/sbin/nologin|' "${BR}/etc/passwd"
# Lock password — replace hash field with '!' in shadow
if [ -f "${BR}/etc/shadow" ]; then
    python3 -c "
import sys
lines = open('${BR}/etc/shadow').readlines()
out = []
for l in lines:
    parts = l.split(':')
    if parts[0] == 'root' and len(parts) >= 2 and parts[1] not in ('!', '!!', '*'):
        parts[1] = '!'
        out.append(':'.join(parts))
    else:
        out.append(l)
open('${BR}/etc/shadow','w').writelines(out)
"
fi
echo "[P2] E: root locked (nologin, no password)"

# ---------------------------------------------------------------------------
# F. Swap disable
# ---------------------------------------------------------------------------
# Remove swap entries from /etc/fstab
if [ -f "${BR}/etc/fstab" ]; then
    grep -v '\bswap\b' "${BR}/etc/fstab" > "${BR}/etc/fstab.new" && mv "${BR}/etc/fstab.new" "${BR}/etc/fstab"
fi
# Mask every known swap service
for svc in systemd-zram-setup@.service zram-config.service dphys-swapfile.service \
           zramswap.service swapfile.service; do
    defer_mask "$svc"
done
echo "[P2] F: swap disabled"

# ---------------------------------------------------------------------------
# G. Core dump disable — coredump.conf (Storage=none) + ulimit via limits.d
# ---------------------------------------------------------------------------
mkdir -p "${BR}/etc/systemd"
cat > "${BR}/etc/systemd/coredump.conf" <<'CDEOF'
# ExamOS P2 — Core dump disabled
# Core dumps must not be written anywhere on ExamOS candidate hardware.
# They may contain exam answers, decryption keys, or candidate PII.
[Coredump]
Storage=none
Compress=no
ProcessSizeMax=0
ExternalSizeMax=0
JournalSizeMax=0
MaxUse=0
KeepFree=0
CDEOF

# Prevent coredumps via PAM limits as a second layer
mkdir -p "${BR}/etc/security/limits.d"
cat > "${BR}/etc/security/limits.d/99-examos-nodump.conf" <<'LIMEOF'
# ExamOS P2: disable core dumps for all users
*    hard    core    0
*    soft    core    0
root hard    core    0
root soft    core    0
LIMEOF

# Disable systemd-coredump.service and socket if they exist
defer_mask systemd-coredump.service systemd-coredump.socket
echo "[P2] G: core dump disabled (coredump.conf + limits.d + service masked)"

# ---------------------------------------------------------------------------
# H. AppArmor — verify enforce mode, enable at boot
# ---------------------------------------------------------------------------
CHROMIUM_PROFILE="${BR}/etc/apparmor.d/examos-kiosk"
LEGACY_CHROMIUM_PROFILE="${BR}/etc/apparmor.d/usr.bin.chromium"
if [ ! -s "$CHROMIUM_PROFILE" ] ||
   ! grep -Fxq 'profile examos-kiosk /{usr/bin,usr/lib/chromium}/chromium flags=(enforce) {' "$CHROMIUM_PROFILE"; then
    echo "[P2] FAIL: canonical Chromium AppArmor profile is missing or not enforcing" >&2
    exit 1
fi
rm -f -- "$LEGACY_CHROMIUM_PROFILE" "${BR}/etc/apparmor.d/chromium"
echo "[P2] H: canonical AppArmor profile enforced; conflicting legacy attachment removed"
enable_required_unit apparmor.service
echo "[P2] H: AppArmor enabled"

# ---------------------------------------------------------------------------
# I. nftables — start BEFORE any network interface is usable
# ---------------------------------------------------------------------------
mkdir -p "${BR}/etc/systemd/system/nftables.service.d"
cat > "${BR}/etc/systemd/system/nftables.service.d/p2-ordering.conf" <<'NFTEOF'
[Unit]
DefaultDependencies=no
After=local-fs.target
Before=network-pre.target NetworkManager.service systemd-networkd.service

[Service]
ExecStartPre=/usr/sbin/nft --check --file /etc/nftables.conf
ExecStopPost=/bin/sh -c '\
  /usr/sbin/nft flush ruleset 2>/dev/null; \
  /usr/sbin/nft add table inet examos_failsafe; \
  /usr/sbin/nft add chain inet examos_failsafe input  "{ type filter hook input  priority -200; policy drop; }"; \
  /usr/sbin/nft add chain inet examos_failsafe output "{ type filter hook output priority -200; policy drop; }"; \
  /usr/sbin/nft add chain inet examos_failsafe forward "{ type filter hook forward priority -200; policy drop; }"; \
  echo "[ExamOS-FW] Emergency fail-closed table active"'
NFTEOF

enable_required_unit nftables.service
echo "[P2] I: nftables ordered before network-pre.target"

# ---------------------------------------------------------------------------
# J. USB default-deny — write authorized_default=0 to every USB host
#    controller at the earliest possible boot stage, before udev fires.
# ---------------------------------------------------------------------------
# The service is defined as a static overlay file (examos-usb-lockdown.service).
# Here we only ensure it is enabled (symlink created).
enable_required_unit examos-usb-lockdown.service
enable_required_unit usbguard.service
echo "[P2] J: examos-usb-lockdown.service enabled"

# ---------------------------------------------------------------------------
# K. Module lock — one-way kernel.modules_disabled=1 after all drivers load
# ---------------------------------------------------------------------------
# Service is a static overlay file (examos-module-lock.service).
enable_required_unit examos-module-lock.service
echo "[P2] K: examos-module-lock.service enabled"

# ---------------------------------------------------------------------------
# L. Lockdown-fail guard target — defined in overlay; just enable it
# ---------------------------------------------------------------------------
# examos-lockdown-failed.target conflicts with graphical.target.
# Any OnFailure= referencing it will block kiosk startup.
echo "[P2] L: lockdown-fail guard target in overlay"

# ---------------------------------------------------------------------------
# M. Mount unit enables (tmpfs for /tmp /home/exam /dev/shm /var/log)
# ---------------------------------------------------------------------------
for unit in tmp.mount home-exam.mount var-log.mount; do
    enable_required_unit "$unit"
done
enable_required_unit examos-dev-shm-hardening.service
enable_required_unit examos-kiosk-readiness.service
echo "[P2] M: tmpfs mount units enabled"

# ---------------------------------------------------------------------------
# N. tmpfiles.d — create runtime log directories on tmpfs at boot
# ---------------------------------------------------------------------------
mkdir -p "${BR}/etc/tmpfiles.d"
cat > "${BR}/etc/tmpfiles.d/examos-runtime.conf" <<'TMPEOF'
# ExamOS P2 — runtime directory skeleton
# Created fresh on every boot from tmpfs; no data persists.
# Format: type path mode uid gid age argument
d  /var/log/examos          0750  root            root            -  -
d  /var/log/journal         0755  root            systemd-journal -  -
d  /run/examos              0755  root            root            -  -
d  /run/user/1000           0700  exam            exam            -  -
TMPEOF
echo "[P2] N: tmpfiles.d skeleton written"

# ---------------------------------------------------------------------------
# O. Unnecessary service mask
# ---------------------------------------------------------------------------
for svc in \
    cron crond atd \
    avahi-daemon avahi-daemon.socket \
    bluetooth.service bluetooth.socket \
    cups cups-browsed \
    ModemManager \
    NetworkManager-wait-online \
    apt-daily.service apt-daily.timer \
    apt-daily-upgrade.service apt-daily-upgrade.timer \
    motd-news.service motd-news.timer \
    systemd-rfkill.service systemd-rfkill.socket \
    fwupd fwupd-refresh.service \
    whoopsie apport; do
    defer_mask "$svc"
done
echo "[P2] O: unnecessary services masked"

# ---------------------------------------------------------------------------
# P. P2 configuration file — machine-readable control manifest
# ---------------------------------------------------------------------------
mkdir -p "${BR}/etc/examos"
cat > "${BR}/etc/examos/p2-config.conf" <<'CFGEOF'
# ExamOS Phase 2 — Lockdown Configuration Manifest
# Read by p2-startup-validator.sh at boot.
# Do NOT store credentials, tokens, or private keys in this file.

PHASE=P2
IMAGE_VERSION=0.3.0
BUILD_PROFILE=release

# Mandatory controls — validator checks each key is exactly "1"
DM_VERITY_REQUIRED=1
LOCKDOWN_MODE=confidentiality
MODULE_LOCK_ENABLED=1
SWAP_DISABLED=1
COREDUMP_DISABLED=1
IPV6_DISABLED=1
USB_DEFAULT_DENY=1
APPARMOR_ENFORCE=1
NFTABLES_BEFORE_NETWORK=1
KIOSK_HARDENED=1
NO_LOGIN_PATHS=1

# Policy version tags — increment when corresponding policy file changes
CHROMIUM_POLICY_VERSION=p2.1
USB_POLICY_VERSION=p2.1
FIREWALL_POLICY_VERSION=p2.1
SUPPORTED_KERNEL_PROFILE=debian-trixie-amd64

# Runtime-resolved values (filled by p2-startup-validator.sh)
# EXAM_URL — read from /etc/examos/exam.conf; startup blocks if NOT_CONFIGURED
# CONTROLLED_DNS_ADDRESS — set at deployment in /etc/examos/exam.conf

FIREWALL_BACKEND=nftables
CFGEOF
chmod 0644 "${BR}/etc/examos/p2-config.conf"
echo "[P2] P: p2-config.conf written"

# ---------------------------------------------------------------------------
# Q. systemd wants symlinks — real symlinks inside the chroot
# ---------------------------------------------------------------------------
# mkosi overlay can carry pre-created symlinks but Windows hosts cannot store
# Unix symlinks in the source tree.  We create them here inside the chroot.

SYSTEMD="${BR}/etc/systemd/system"

# local-fs.target.wants
mkdir -p "${SYSTEMD}/local-fs.target.wants"
for unit in tmp.mount home-exam.mount var-log.mount; do
    ln -sf "../${unit}" "${SYSTEMD}/local-fs.target.wants/${unit}"
done

# sysinit.target.wants
mkdir -p "${SYSTEMD}/sysinit.target.wants"
for unit in examos-dev-shm-hardening.service examos-usb-lockdown.service; do
    ln -sf "../${unit}" "${SYSTEMD}/sysinit.target.wants/${unit}"
done

# graphical.target.wants
mkdir -p "${SYSTEMD}/graphical.target.wants"
ln -sf "../examos-module-lock.service" \
    "${SYSTEMD}/graphical.target.wants/examos-module-lock.service"
ln -sf "../examos-kiosk.service" \
    "${SYSTEMD}/graphical.target.wants/examos-kiosk.service"

# multi-user.target.wants (existing P1 services, restored so they are not lost)
mkdir -p "${SYSTEMD}/multi-user.target.wants"
for svc in examos-server.service examos-agent.service; do
    if [ ! -f "${SYSTEMD}/${svc}" ]; then
        echo "[P2] FAIL: required service unit is missing: ${svc}" >&2
        exit 1
    fi
    ln -sf "../${svc}" "${SYSTEMD}/multi-user.target.wants/${svc}"
done

# Also enable graphical.target for kiosk
enable_required_unit examos-kiosk.service

echo "[P2] Q: systemd wants symlinks created"

# A unit can be deferred by the overlay scan and again by an explicit rule.
sort -u -o "$MASK_LIST" "$MASK_LIST"

echo "[P2] R: $(wc -l < "$MASK_LIST") unit masks deferred to the post-preset finalize step"

echo "=== [ExamOS P2] All lockdown controls applied ==="
