#!/usr/bin/env bash
set -e

cd "/mnt/d/SEB BRO" || exit 1

OVERLAY="/home/krant/sppio-test/examos-gui-test.qcow2"

echo "=== 1. Ensuring disposable overlay exists backed by output/examos-flat.vmdk ==="
if [ ! -f "$OVERLAY" ]; then
  qemu-img create -f qcow2 -F raw -b "$PWD/output/examos-flat.vmdk" "$OVERLAY"
fi

echo "=== 2. Creating VM in-guest patch script ==="
cat << 'IN_GUEST_EOF' > /tmp/in-guest-fix.sh
#!/bin/bash
set -x

echo "=== IN-GUEST PATCHING START ==="
mount -o remount,rw /

# 1. Mount host share if available
mkdir -p /mnt/host
mount -t 9p -o trans=virtio,version=9p2000.L hostshare /mnt/host 2>/dev/null || true

# 2. Update HTML pages from repo
mkdir -p /usr/share/examos
if [ -d /mnt/host/image/overlay/usr/share/examos ]; then
  cp -rf /mnt/host/image/overlay/usr/share/examos/* /usr/share/examos/
fi
chmod 644 /usr/share/examos/*.html 2>/dev/null || true

# 3. Fix exam user & home
chown -R exam:exam /home/exam 2>/dev/null || true
mkdir -p /home/exam/.config /run/user/1000
chown -R exam:exam /home/exam /run/user/1000
chmod 0700 /run/user/1000

# 4. Install updated kiosk launcher
test -x /mnt/host/image/overlay/usr/local/bin/examos-kiosk-launcher || {
  echo "Missing canonical kiosk launcher" >&2
  exit 1
}
install -m 0755 /mnt/host/image/overlay/usr/local/bin/examos-kiosk-launcher \
  /usr/local/bin/examos-kiosk-launcher

# 5. Write corrected examos-kiosk.service
test -r /mnt/host/image/overlay/etc/systemd/system/examos-kiosk.service || {
  echo "Missing canonical kiosk unit" >&2
  exit 1
}
install -m 0644 /mnt/host/image/overlay/etc/systemd/system/examos-kiosk.service \
  /etc/systemd/system/examos-kiosk.service

test -r /mnt/host/image/overlay/etc/systemd/system/examos-proctor.service || {
  echo "Missing canonical proctor unit" >&2
  exit 1
}
install -m 0644 /mnt/host/image/overlay/etc/systemd/system/examos-proctor.service \
  /etc/systemd/system/examos-proctor.service

test -x /mnt/host/image/overlay/usr/local/bin/examos-kiosk-readiness || {
  echo "Missing canonical kiosk readiness probe" >&2
  exit 1
}
install -m 0755 /mnt/host/image/overlay/usr/local/bin/examos-kiosk-readiness \
  /usr/local/bin/examos-kiosk-readiness
test -r /mnt/host/image/overlay/etc/systemd/system/examos-kiosk-readiness.service || {
  echo "Missing canonical kiosk readiness unit" >&2
  exit 1
}
install -m 0644 /mnt/host/image/overlay/etc/systemd/system/examos-kiosk-readiness.service \
  /etc/systemd/system/examos-kiosk-readiness.service
install -D -m 0644 /mnt/host/image/overlay/etc/systemd/system/graphical.target.d/examos-kiosk-readiness.conf \
  /etc/systemd/system/graphical.target.d/examos-kiosk-readiness.conf

# Enable the service
systemctl enable examos-kiosk.service 2>/dev/null || true

sync
echo "=== IN-GUEST PATCHING COMPLETE ==="
poweroff -f
IN_GUEST_EOF
chmod 755 /tmp/in-guest-fix.sh

echo "=== 3. Executing patch inside VM via QEMU direct kernel boot ==="
qemu-system-x86_64 \
  -machine q35,accel=kvm \
  -cpu host \
  -m 2048 \
  -kernel "/mnt/d/SEB BRO/image/examos.vmlinuz" \
  -initrd "/mnt/d/SEB BRO/image/examos.initrd" \
  -append "root=/dev/vda2 rw console=ttyS0 init=/bin/bash" \
  -drive file="$OVERLAY",format=qcow2,if=virtio \
  -virtfs local,path="/mnt/d/SEB BRO",mount_tag=hostshare,security_model=none \
  -nographic \
  -no-reboot < /tmp/in-guest-fix.sh

echo "=== 4. Overlay successfully patched! ==="
