#!/usr/bin/env bash
# =============================================================================
# ExamOS Image Build - Enterprise OS Hardening
#
# Applied while the image is built, so the shipped appliance starts in its
# hardened state rather than being hardened after the fact.
# =============================================================================
set -euo pipefail

echo "=== [ExamOS Build] Applying Enterprise OS Hardening ==="

# ----------------------------------------------------------------------------
# 1. Kernel and process posture
#
# The shipped configuration in the overlay is authoritative and is not
# replaced here. The settings are only written when the overlay does not
# provide them, so the hardening pass can never weaken a shipped posture.
# ----------------------------------------------------------------------------
if [ ! -f /etc/sysctl.d/99-examos-security.conf ]; then
    cat > /etc/sysctl.d/99-examos-security.conf <<'EOF'
# ExamOS kernel posture.
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.unprivileged_bpf_disabled = 1
kernel.yama.ptrace_scope = 3
kernel.core_pattern = |/bin/false
kernel.randomize_va_space = 2
kernel.perf_event_paranoid = 3
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.suid_dumpable = 0
net.core.bpf_jit_harden = 2
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.default.log_martians = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.default.send_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.all.log_martians = 1
EOF
fi
sysctl --system >/dev/null 2>&1 || true

# ----------------------------------------------------------------------------
# 2. Services
# ----------------------------------------------------------------------------
systemctl enable apparmor 2>/dev/null || true
systemctl enable nftables 2>/dev/null || true
systemctl enable examos-server 2>/dev/null || true
systemctl enable examos-agent 2>/dev/null || true
systemctl enable examos-kiosk 2>/dev/null || true
systemctl enable examos-proctor 2>/dev/null || true

# ----------------------------------------------------------------------------
# 3. Console and remote access
#
# The appliance has no operator console and no remote shell. Recovery is
# performed from the signed recovery medium, not from a login prompt.
# ----------------------------------------------------------------------------
for i in 1 2 3 4 5 6; do
    systemctl mask "getty@tty${i}.service" 2>/dev/null || true
done
systemctl disable ssh 2>/dev/null || true
systemctl disable sshd 2>/dev/null || true
systemctl mask ssh.service 2>/dev/null || true
systemctl mask sshd.service 2>/dev/null || true
systemctl disable cron 2>/dev/null || true
systemctl mask cron.service 2>/dev/null || true

# ----------------------------------------------------------------------------
# 4. System identity
# ----------------------------------------------------------------------------
echo "examos-device" > /etc/hostname
echo "ExamOS Secure Examination Appliance" > /etc/issue
rm -f /etc/motd

# ----------------------------------------------------------------------------
# 5. State directories
# ----------------------------------------------------------------------------
install -d -o root -g root -m 0750 /var/log/examos
install -d -o root -g root -m 0750 /var/lib/examos
install -d -o root -g root -m 0750 /run/examos
install -d -o root -g root -m 0755 /etc/examos/models

# ----------------------------------------------------------------------------
# 6. Password policy
#
# The administrator credential is the last human-held secret on the
# appliance, so the policy is enforced by the system rather than by the
# application.
# ----------------------------------------------------------------------------
if [ -f /etc/login.defs ]; then
    sed -i \
        -e 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS\t90/' \
        -e 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS\t1/' \
        -e 's/^PASS_WARN_AGE.*/PASS_WARN_AGE\t14/' \
        -e 's/^UMASK.*/UMASK\t0077/' \
        /etc/login.defs
fi

# ----------------------------------------------------------------------------
# 7. Kernel lockdown
#
# The appliance only provides meaningful attestation while the kernel is in
# confidentiality lockdown. The examination components verify this at
# startup, so an image that booted without it is refused.
# ----------------------------------------------------------------------------
if [ -r /sys/kernel/security/lockdown ]; then
    echo "[ExamOS Build] Kernel lockdown modes: $(cat /sys/kernel/security/lockdown)"
    if ! grep -q '\[confidentiality\]' /sys/kernel/security/lockdown 2>/dev/null; then
        echo "[ExamOS Build] WARNING: confidentiality lockdown is not active on the build host." >&2
        echo "[ExamOS Build] The appliance refuses to start its examination services without it." >&2
    fi
else
    echo "[ExamOS Build] WARNING: kernel lockdown is not exposed on this kernel." >&2
fi

# ----------------------------------------------------------------------------
# 8. Read-only system paths
# ----------------------------------------------------------------------------
install -d -o root -g root -m 0755 /etc/examos/sealed
chown root:root /etc/examos/sealed
chmod 0700 /etc/examos/sealed

echo "=== [ExamOS Build] OS Hardening complete ==="
