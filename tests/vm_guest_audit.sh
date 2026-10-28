#!/bin/bash
# tests/vm_guest_audit.sh — Runs as init in disposable VM to audit effective appliance runtime state
set +e

# Mount required kernel pseudo-filesystems when running as init
mount -t proc proc /proc 2>/dev/null || true
mount -t sysfs sysfs /sys 2>/dev/null || true
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true

echo "=== C1_START ==="
for u in getty@tty1 getty@tty2 getty@tty3 getty@tty4 getty@tty5 getty@tty6 autovt@ console-getty debug-shell; do
  if [ -L "/etc/systemd/system/${u}.service" ]; then
    target=$(readlink "/etc/systemd/system/${u}.service")
  else
    target="not_masked"
  fi
  echo "MASK_CHECK: ${u}.service -> $target"
done
echo "=== C1_END ==="

echo "=== C2_START ==="
if [ -L /etc/systemd/system/serial-getty@ttyS0.service ]; then
  serial_target=$(readlink /etc/systemd/system/serial-getty@ttyS0.service)
else
  serial_target="unmasked"
fi
echo "SERIAL_CHECK: serial-getty@ttyS0.service -> $serial_target"
echo "=== C2_END ==="

echo "=== B1_START ==="
exam_uid=$(id -u exam 2>/dev/null || echo 'missing')
echo "EXAM_USER_UID: $exam_uid"
if [ -f /proc/sys/kernel/unprivileged_userns_clone ]; then
  userns_val=$(cat /proc/sys/kernel/unprivileged_userns_clone)
else
  userns_val="1"
fi
echo "USERNS_SYSCTL: $userns_val"
unshare_res=$(su -s /bin/sh exam -c 'unshare -U true 2>&1 && echo OK || echo FAIL')
echo "EXAM_UNSHARE_TEST: $unshare_res"
echo "=== B1_END ==="

echo "=== B2_START ==="
exit_code=0
/usr/local/bin/examos-kiosk-launcher --no-sandbox 2>&1 || exit_code=$?
echo "EXIT_NO_SANDBOX: $exit_code"
root_exit=0
/usr/local/bin/examos-kiosk-launcher 2>&1 || root_exit=$?
echo "EXIT_ROOT_UID: $root_exit"
echo "=== B2_END ==="

echo "=== B3_START ==="
if [ -f /etc/apparmor.d/examos-kiosk ]; then
  echo "APPARMOR_FILE: present"
  grep -E 'userns|deny capability ptrace|deny /proc' /etc/apparmor.d/examos-kiosk || true
else
  echo "APPARMOR_FILE: missing"
fi
echo "=== B3_END ==="

echo "=== AUDIT_COMPLETE ==="
sync
echo 1 > /proc/sys/kernel/sysrq 2>/dev/null || true
echo o > /proc/sysrq-trigger 2>/dev/null || true
