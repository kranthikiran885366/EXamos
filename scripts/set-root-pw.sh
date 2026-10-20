#!/usr/bin/env bash
set -euo pipefail

WORKSPACE="/mnt/d/SEB BRO"
RAW_IMG="$WORKSPACE/image/examos.raw"

LOOPDEV=$(sudo losetup -fP --show "$RAW_IMG")
trap 'sudo umount /mnt/examos_rw 2>/dev/null || true; sudo losetup -d "$LOOPDEV" 2>/dev/null || true' EXIT

sudo mkdir -p /mnt/examos_rw
sudo mount "${LOOPDEV}p2" /mnt/examos_rw

# Set root password to "root"
ROOT_HASH='$6$examos$oZ0l4aZ9mSre5HLtcD1iCENxcNs2TEEE4zAMOKxKdbV59iH6.jrH/fpLCyhFC7g0jGteERKLNDVXywctoKuut0'

sudo python3 -c "
hash_val = '''$ROOT_HASH'''
with open('/mnt/examos_rw/etc/shadow', 'r') as f:
    lines = f.readlines()
new_lines = []
for line in lines:
    if line.startswith('root:'):
        parts = line.split(':')
        parts[1] = hash_val
        new_lines.append(':'.join(parts))
    else:
        new_lines.append(line)
with open('/mnt/examos_rw/etc/shadow', 'w') as f:
    f.writelines(new_lines)
"

# Also ensure exam user exists with password "exam"
if ! grep -q '^exam:' /mnt/examos_rw/etc/passwd; then
    sudo python3 -c "
with open('/mnt/examos_rw/etc/passwd', 'a') as f:
    f.write('exam:x:1000:1000:ExamOS Runtime User:/home/exam:/bin/bash\n')
with open('/mnt/examos_rw/etc/group', 'a') as f:
    f.write('exam:x:1000:\n')
with open('/mnt/examos_rw/etc/shadow', 'a') as f:
    f.write('exam:$ROOT_HASH:20735:0:99999:7:::\n')
"
    sudo mkdir -p /mnt/examos_rw/home/exam
    sudo chown -R 1000:1000 /mnt/examos_rw/home/exam
fi

# Enable getty on tty1
sudo rm -f /mnt/examos_rw/etc/systemd/system/getty.target.wants/getty@tty1.service 2>/dev/null || true

sudo sync
echo "SUCCESS: root password set to 'root', exam password set to 'root'"
