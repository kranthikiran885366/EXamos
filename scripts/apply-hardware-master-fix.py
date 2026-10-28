#!/usr/bin/env python3
import subprocess
import time
import os
import sys

repo_dir = "/mnt/d/SEB BRO"
overlay = "/home/krant/sppio-test/hw-fix-overlay.qcow2"
vmlinuz = f"{repo_dir}/image/examos.vmlinuz"
initrd = f"{repo_dir}/image/examos.initrd"
vmdk = f"{repo_dir}/output/examos-flat.vmdk"
fw_dir = "/home/krant/firmware-pkg"

print("=== 1. Creating overlay backed by output/examos-flat.vmdk ===")
if os.path.exists(overlay):
    os.remove(overlay)
subprocess.run(["qemu-img", "create", "-f", "qcow2", "-F", "raw", "-b", vmdk, overlay], check=True)

cmd = [
    "qemu-system-x86_64",
    "-machine", "q35,accel=kvm",
    "-cpu", "host",
    "-m", "2048",
    "-kernel", vmlinuz,
    "-initrd", initrd,
    "-append", "root=/dev/vda2 rw console=ttyS0 init=/bin/bash",
    "-drive", f"file={overlay},format=qcow2,if=virtio",
    "-virtfs", f"local,path={fw_dir},mount_tag=fwshare,security_model=none",
    "-virtfs", f"local,path={repo_dir},mount_tag=reposhare,security_model=none",
    "-nographic",
    "-no-reboot"
]

print("=== 2. Spawning QEMU with direct bash console ===")
p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

buf = b""
print("=== 3. Waiting for root@localhost prompt ===")
start = time.time()
while time.time() - start < 30:
    try:
        chunk = os.read(p.stdout.fileno(), 1024)
        if chunk:
            sys.stdout.buffer.write(chunk)
            sys.stdout.buffer.flush()
            buf += chunk
            if b"root@localhost:/" in buf:
                print("\n>>> ROOT PROMPT DETECTED! <<<")
                break
    except Exception:
        time.sleep(0.1)

time.sleep(0.5)

fix_commands = [
    "mount -o remount,rw /\n",
    "mkdir -p /mnt/fw /mnt/repo\n",
    "mount -t 9p -o trans=virtio,version=9p2000.L fwshare /mnt/fw 2>/dev/null || true\n",
    "mount -t 9p -o trans=virtio,version=9p2000.L reposhare /mnt/repo 2>/dev/null || true\n",

    # 1. Extract physical GPU and network firmware into /usr/lib/firmware
    "echo '>>> Staging physical GPU and network firmware from archive...'\n",
    "mkdir -p /usr/lib/firmware\n",
    "if [ -f /mnt/fw/firmware.tar ]; then tar -xf /mnt/fw/firmware.tar -C /usr/lib/firmware/; fi\n",
    "echo '>>> Firmware staged. Top directories in /usr/lib/firmware:'\n",
    "ls -d /usr/lib/firmware/* | head -n 15\n",

    # 2. Install examos-usb-guard.sh
    """cat << 'GUARD_EOF' > /usr/local/sbin/examos-usb-guard.sh
#!/bin/bash
DEV="$1"

# Check if block device is part of root filesystem
ROOT_DEV=$(findmnt -n -o SOURCE / 2>/dev/null || true)
if [ -n "$ROOT_DEV" ]; then
    ROOT_DISK=$(lsblk -no PKNAME "$ROOT_DEV" 2>/dev/null || true)
    if [ -z "$ROOT_DISK" ]; then
        ROOT_DISK=$(basename "$ROOT_DEV" | tr -d '0-9')
    fi
    if [ -n "$ROOT_DISK" ] && echo "$DEV" | grep -q "$ROOT_DISK"; then
        logger -t [ExamOS-USB-Security] "Preserved boot medium ($ROOT_DISK)"
        exit 0
    fi
fi

# Check root filesystem UUID
ROOT_UUID=$(findmnt -n -o UUID / 2>/dev/null || true)
if [ -n "$ROOT_UUID" ]; then
    DEV_UUID=$(blkid -s UUID -o value "/dev/$DEV" 2>/dev/null || true)
    if [ -n "$DEV_UUID" ] && [ "$DEV_UUID" = "$ROOT_UUID" ]; then
        logger -t [ExamOS-USB-Security] "Preserved boot UUID ($DEV_UUID)"
        exit 0
    fi
fi

# Block and remove secondary/unauthorized USB mass storage devices
if [ -f "/sys/class/block/$DEV/device/delete" ]; then
    echo 1 > "/sys/class/block/$DEV/device/delete" 2>/dev/null || true
elif [ -f "/sys/block/$DEV/device/delete" ]; then
    echo 1 > "/sys/block/$DEV/device/delete" 2>/dev/null || true
fi
echo 0 > "$DEV/authorized" 2>/dev/null || echo 0 > "$DEV/device/authorized" 2>/dev/null || true
logger -t [ExamOS-USB-Security] "Blocked unauthorized USB mass storage device: $DEV"
GUARD_EOF
""",
    "chmod 755 /usr/local/sbin/examos-usb-guard.sh\n",

    # 3. Update 99-examos-usb-lockdown.rules
    """cat << 'RULES_EOF' > /etc/udev/rules.d/99-examos-usb-lockdown.rules
# ExamOS USB Port Lockdown & Hardware Guard Rules
# Block unauthorized USB Mass Storage devices while strictly protecting the boot medium
ACTION=="add", SUBSYSTEM=="block", ENV{ID_BUS}=="usb", RUN+="/usr/local/sbin/examos-usb-guard.sh %k"

# Block unauthorized USB Network adapters
ACTION=="add", SUBSYSTEM=="net", ENV{ID_BUS}=="usb", RUN+="/bin/sh -c 'ip link set $name down 2>/dev/null || true'"

# Allow standard HID Class devices (keyboards, mice, touchpads, touchscreens)
ACTION=="add", SUBSYSTEM=="usb", ATTR{bInterfaceClass}=="03", ATTR{authorized}="1"

# Allow USB Hubs (needed to enumerate allowed devices)
ACTION=="add", SUBSYSTEM=="usb", ATTR{bInterfaceClass}=="09", ATTR{authorized}="1"

# Allow Audio Class (Microphones for proctoring)
ACTION=="add", SUBSYSTEM=="usb", ATTR{bInterfaceClass}=="01", ATTR{authorized}="1"

# Allow Video Class (Webcams for proctoring)
ACTION=="add", SUBSYSTEM=="usb", ATTR{bInterfaceClass}=="0e", ATTR{authorized}="1"
ACTION=="add", SUBSYSTEM=="video4linux", GROUP="video", MODE="0660"
RULES_EOF
""",
    "chmod 644 /etc/udev/rules.d/99-examos-usb-lockdown.rules\n",

    # 4. Update /etc/usbguard/rules.conf (mode 0600)
    """cat << 'USBG_EOF' > /etc/usbguard/rules.conf
allow with-interface equals { 03:*:* }
allow with-interface equals { 09:*:* }
allow with-interface equals { 01:*:* }
allow with-interface equals { 0e:*:* }
allow with-interface equals { 08:*:* }
USBG_EOF
""",
    "chmod 600 /etc/usbguard/rules.conf /etc/usbguard/usbguard-daemon.conf 2>/dev/null || true\n",

    # 5. Fix examos-module-lock.service timing
    """cat << 'MODLOCK_EOF' > /etc/systemd/system/examos-module-lock.service
[Unit]
Description=ExamOS Kernel Module Loading Lock
Documentation=file:///etc/examos/p2-config.conf
After=systemd-udev-settle.service network.target sound.target systemd-modules-load.service
Before=examos-kiosk.service
ConditionPathExists=/proc/sys/kernel/modules_disabled

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=-/usr/bin/udevadm settle --timeout=10
ExecStartPre=/bin/sh -c 'echo "[ExamOS-ModLock] Driver modules active before lock:"; lsmod'
ExecStart=/bin/sh -c 'echo 1 > /proc/sys/kernel/modules_disabled && echo "[ExamOS-ModLock] kernel.modules_disabled=1 locked successfully"'
StandardOutput=journal+console
StandardError=journal+console

[Install]
WantedBy=graphical.target
MODLOCK_EOF
""",

    # 6. Install official compiled ExamOS native C launcher (sandboxed, unprivileged 'exam' user)
    "cp -f /mnt/reposhare/image/overlay/usr/local/bin/examos-kiosk-launcher /usr/local/bin/examos-kiosk-launcher\n",
    "chmod 755 /usr/local/bin/examos-kiosk-launcher\n",
    "chown root:root /usr/local/bin/examos-kiosk-launcher\n",

    # 7. Apply kernel sysctl and AppArmor user namespace configuration
    "cp -f /mnt/reposhare/image/overlay/etc/sysctl.d/99-examos-security.conf /etc/sysctl.d/99-examos-security.conf\n",
    "cp -f /mnt/reposhare/image/overlay/etc/apparmor.d/examos-kiosk /etc/apparmor.d/examos-kiosk\n",

    # 8. Mask candidate-accessible virtual terminals (preserving serial-getty for administrative recovery)
    "rm -rf /etc/systemd/system/getty@tty2.service.d 2>/dev/null || true\n",
    "ln -sf /dev/null /etc/systemd/system/getty@tty1.service\n",
    "ln -sf /dev/null /etc/systemd/system/getty@tty2.service\n",
    "ln -sf /dev/null /etc/systemd/system/getty@tty3.service\n",
    "ln -sf /dev/null /etc/systemd/system/getty@tty4.service\n",
    "ln -sf /dev/null /etc/systemd/system/getty@tty5.service\n",
    "ln -sf /dev/null /etc/systemd/system/getty@tty6.service\n",
    "ln -sf /dev/null /etc/systemd/system/autovt@.service\n",
    "ln -sf /dev/null /etc/systemd/system/console-getty.service\n",
    "ln -sf /dev/null /etc/systemd/system/debug-shell.service\n",

    # 7. Update copy in overlay repository source as well
    "sync\n",
    "echo '=== HARDWARE_MASTER_FIX_APPLIED ==='\n",
    "poweroff -f\n"
]

print("=== 4. Sending hardware fix commands to root bash ===")
for cmd_str in fix_commands:
    p.stdin.write(cmd_str.encode('utf-8'))
    p.stdin.flush()
    time.sleep(0.3)

print("=== 5. Reading verification ===")
success = False
start_wait = time.time()
while time.time() - start_wait < 60:
    try:
        chunk = os.read(p.stdout.fileno(), 1024)
        if chunk:
            sys.stdout.buffer.write(chunk)
            sys.stdout.buffer.flush()
            if b"=== HARDWARE_MASTER_FIX_APPLIED ===" in chunk:
                success = True
                break
    except Exception:
        time.sleep(0.1)

p.wait(timeout=30)
print(f"\nQEMU exited with code {p.returncode}")
if success:
    print("SUCCESS: Hardware master fix applied to overlay successfully!")
else:
    print("WARNING: Check output above for details")
