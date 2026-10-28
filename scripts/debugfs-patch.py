#!/usr/bin/env python3
"""
scripts/debugfs-patch.py
Directly and safely updates ext4 partition of appliance images:
- /usr/local/bin/examos-kiosk-launcher (compiled C binary, 40272 bytes)
- /etc/sysctl.d/99-examos-security.conf (unprivileged_userns_clone = 1)
- /etc/apparmor.d/examos-kiosk (userns,)
- /etc/systemd/system/ masks for getty@tty1..6, autovt@, console-getty, debug-shell
"""

import subprocess
import os
import shutil

REPO_DIR = "/mnt/d/SEB BRO"
OFFSET = "537919488"
TARGETS = [
    f"{REPO_DIR}/image/examos.raw",
    f"{REPO_DIR}/output/examos-flat.vmdk"
]

# Stage files into /tmp to avoid whitespace issues in paths with debugfs
shutil.copy2(f"{REPO_DIR}/image/overlay/usr/local/bin/examos-kiosk-launcher", "/tmp/examos-kiosk-launcher")
shutil.copy2(f"{REPO_DIR}/image/overlay/etc/sysctl.d/99-examos-security.conf", "/tmp/99-examos-security.conf")
shutil.copy2(f"{REPO_DIR}/image/overlay/etc/apparmor.d/examos-kiosk", "/tmp/examos-kiosk")

DEBUG_SCRIPT = """
rm /usr/local/bin/examos-kiosk-launcher
write /tmp/examos-kiosk-launcher /usr/local/bin/examos-kiosk-launcher
sif /usr/local/bin/examos-kiosk-launcher mode 0100755

rm /etc/sysctl.d/99-examos-security.conf
write /tmp/99-examos-security.conf /etc/sysctl.d/99-examos-security.conf
sif /etc/sysctl.d/99-examos-security.conf mode 0100644

rm /etc/apparmor.d/examos-kiosk
write /tmp/examos-kiosk /etc/apparmor.d/examos-kiosk
sif /etc/apparmor.d/examos-kiosk mode 0100644

symlink /etc/systemd/system/getty@tty1.service /dev/null
symlink /etc/systemd/system/getty@tty2.service /dev/null
symlink /etc/systemd/system/getty@tty3.service /dev/null
symlink /etc/systemd/system/getty@tty4.service /dev/null
symlink /etc/systemd/system/getty@tty5.service /dev/null
symlink /etc/systemd/system/getty@tty6.service /dev/null
symlink /etc/systemd/system/autovt@.service /dev/null
symlink /etc/systemd/system/console-getty.service /dev/null
symlink /etc/systemd/system/debug-shell.service /dev/null
"""

for target in TARGETS:
    if not os.path.exists(target):
        continue
    print(f"Applying debugfs patch to {target} (offset {OFFSET})...")
    p = subprocess.Popen(['debugfs', '-w', f"{target}?offset={OFFSET}"],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out, err = p.communicate(DEBUG_SCRIPT)
    print(f"debugfs returned code {p.returncode}")

print("\nVerifying patched image filesystem contents...")
chk = subprocess.run(['debugfs', '-R', 'ls -l /usr/local/bin', f"{REPO_DIR}/image/examos.raw?offset={OFFSET}"],
                     capture_output=True, text=True)
for line in chk.stdout.splitlines():
    if "examos-kiosk-launcher" in line:
        print("  Launcher:", line.strip())

chk2 = subprocess.run(['debugfs', '-R', 'ls -l /etc/systemd/system', f"{REPO_DIR}/image/examos.raw?offset={OFFSET}"],
                      capture_output=True, text=True)
for line in chk2.stdout.splitlines():
    if "getty" in line or "autovt" in line or "debug-shell" in line:
        print("  Systemd mask:", line.strip())

print("\nVerifying sysctl and apparmor...")
chk3 = subprocess.run(['debugfs', '-R', 'stat /etc/sysctl.d/99-examos-security.conf', f"{REPO_DIR}/image/examos.raw?offset={OFFSET}"],
                      capture_output=True, text=True)
print("  sysctl stat:", [l for l in chk3.stdout.splitlines() if "Size:" in l])

chk4 = subprocess.run(['debugfs', '-R', 'stat /etc/apparmor.d/examos-kiosk', f"{REPO_DIR}/image/examos.raw?offset={OFFSET}"],
                      capture_output=True, text=True)
print("  apparmor stat:", [l for l in chk4.stdout.splitlines() if "Size:" in l])

# Fast SHA256 using sha256sum binary
raw_file = f"{REPO_DIR}/image/examos.raw"
print(f"\nRecalculating SHA256 for {raw_file} with sha256sum...")
res = subprocess.run(["sha256sum", raw_file], capture_output=True, text=True)
if res.returncode == 0:
    digest = res.stdout.split()[0]
    sha_file = f"{REPO_DIR}/image/examos.raw.sha256"
    with open(sha_file, "w") as f:
        f.write(f"{digest}  examos.raw\n")
    print(f"Updated {sha_file}: {digest}")
