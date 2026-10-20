#!/bin/bash
# ExamOS Secure Desktop - Fix and Install
# Fixes: policykit-1 → polkitd, re-bootstraps apt, installs packages
set -uo pipefail

RAW="/mnt/d/SEB BRO/image/examos.raw"
MNT="/mnt/examos"

echo "============================================"
echo "  ExamOS Desktop Fix & Install"
echo "============================================"

# Step 0: Mount
echo "[0] Mounting image..."
sudo umount -R "$MNT" 2>/dev/null || true
sudo losetup -D 2>/dev/null || true
sleep 1
sudo losetup -fP "$RAW"
LOOP=$(losetup -j "$RAW" | head -1 | cut -d: -f1)
echo "  Loop: $LOOP"
sudo mkdir -p "$MNT"
sudo mount "${LOOP}p2" "$MNT"

# Bind mounts
sudo mount --bind /dev "$MNT/dev"
sudo mount --bind /dev/pts "$MNT/dev/pts"
sudo mount -t proc proc "$MNT/proc"
sudo mount -t sysfs sysfs "$MNT/sys"
sudo mount -t tmpfs tmpfs "$MNT/tmp"
sudo mount -t tmpfs tmpfs "$MNT/run"
echo "nameserver 8.8.8.8" | sudo tee "$MNT/etc/resolv.conf" > /dev/null
echo "  ✓ Mounted"

# Step 1: Re-bootstrap APT (was deleted by hardening)
echo ""
echo "[1] Re-bootstrapping APT..."

# Check if apt exists
if sudo chroot "$MNT" bash -c 'command -v apt-get' &>/dev/null; then
    echo "  APT still available"
else
    echo "  Re-downloading APT..."
    APTDIR="$MNT/tmp/apt-bootstrap"
    sudo mkdir -p "$APTDIR"
    
    download_pkg() {
        local pkg="$1"
        local url
        url=$(wget -q -O- "http://deb.debian.org/debian/dists/trixie/main/binary-amd64/Packages.xz" 2>/dev/null | \
              xzcat 2>/dev/null | \
              awk -v pkg="$pkg" '/^Package: / { p = ($2 == pkg) } /^Filename: / && p { print $2; exit }')
        if [ -n "$url" ]; then
            wget -q "http://deb.debian.org/debian/${url}" -O "$APTDIR/$(basename "$url")" 2>/dev/null
            echo "    ✓ $pkg"
            return 0
        fi
        echo "    ✗ $pkg"
        return 1
    }
    
    download_pkg "apt"
    download_pkg "libapt-pkg7.0"
    download_pkg "gpgv"
    download_pkg "debian-archive-keyring"
    download_pkg "libxxhash0"
    download_pkg "liblz4-1"
    
    sudo chroot "$MNT" bash -c '
        dpkg --force-depends --force-confnew -i /tmp/apt-bootstrap/*.deb 2>&1 | grep -E "(Setting up|error)" || true
    '
    echo "  ✓ APT re-installed"
fi

# Restore sources.list
sudo mkdir -p "$MNT/etc/apt/sources.list.d"
sudo mkdir -p "$MNT/var/lib/apt/lists/partial"
sudo mkdir -p "$MNT/var/cache/apt/archives/partial"
cat << 'EOF' | sudo tee "$MNT/etc/apt/sources.list" > /dev/null
deb http://deb.debian.org/debian trixie main contrib
deb http://security.debian.org/debian-security trixie-security main contrib
EOF
cat << 'EOF' | sudo tee "$MNT/etc/apt/apt.conf.d/99nosandbox" > /dev/null
APT::Sandbox::User "root";
EOF

# Ensure keyring
KEYRING_URL=$(wget -q -O- "http://deb.debian.org/debian/dists/trixie/main/binary-amd64/Packages.xz" 2>/dev/null | \
    xzcat 2>/dev/null | awk '/^Package: debian-archive-keyring$/{p=1} /^Filename: / && p{print $2; exit}')
if [ -n "$KEYRING_URL" ]; then
    wget -q "http://deb.debian.org/debian/${KEYRING_URL}" -O "$MNT/tmp/keyring.deb" 2>/dev/null
    sudo dpkg-deb -x "$MNT/tmp/keyring.deb" "$MNT/" 2>/dev/null
    sudo cp "$MNT/usr/share/keyrings/debian-archive-"*.gpg "$MNT/etc/apt/trusted.gpg.d/" 2>/dev/null || true
fi

# Step 2: Install desktop packages (FIXED package names)
echo ""
echo "[2] Installing desktop packages..."
sudo chroot "$MNT" bash -c '
export DEBIAN_FRONTEND=noninteractive
export LC_ALL=C
export PATH=/usr/bin:/usr/sbin:/bin:/sbin

echo "  Updating package lists..."
apt-get update -qq 2>&1 | tail -3

echo ""
echo "  Installing Openbox + tint2 desktop..."
# Install in smaller groups to handle any missing packages
CORE="openbox tint2 xorg xinit x11-xserver-utils dbus-x11"
AUDIO="pulseaudio pulseaudio-utils"
POWER="upower"
THEME="adwaita-icon-theme fonts-dejavu-core"
TOOLS="numlockx feh dunst xdotool picom"
AUTH="polkitd pkexec lxpolkit"

for GROUP_NAME in "CORE" "AUDIO" "POWER" "THEME" "TOOLS" "AUTH"; do
    eval PKGS=\$$GROUP_NAME
    echo ""
    echo "  Installing $GROUP_NAME: $PKGS"
    apt-get install -y --no-install-recommends $PKGS 2>&1 | tail -3
    if [ $? -eq 0 ]; then
        echo "    ✓ $GROUP_NAME installed"
    else
        echo "    ⚠ $GROUP_NAME had issues, trying individual packages..."
        for pkg in $PKGS; do
            apt-get install -y --no-install-recommends "$pkg" 2>&1 | tail -1
        done
    fi
done

echo ""
echo "  === Installation Results ==="
for pkg in openbox tint2 xorg pulseaudio upower picom dunst feh numlockx; do
    if dpkg -s "$pkg" &>/dev/null; then
        VER=$(dpkg -s "$pkg" 2>/dev/null | grep "^Version:" | cut -d" " -f2)
        echo "    ✓ $pkg ($VER)"
    else
        echo "    ✗ $pkg MISSING"
    fi
done

echo ""
echo "  Disk usage after install:"
df -h / | tail -1
'

# Step 3: Verify installation success before hardening
echo ""
echo "[3] Verifying installation..."
OPENBOX_OK=$(sudo chroot "$MNT" bash -c 'command -v openbox && echo YES || echo NO')
TINT2_OK=$(sudo chroot "$MNT" bash -c 'command -v tint2 && echo YES || echo NO')
XORG_OK=$(sudo chroot "$MNT" bash -c 'command -v Xorg && echo YES || echo NO')

echo "  Openbox: $OPENBOX_OK"
echo "  tint2:   $TINT2_OK"
echo "  Xorg:    $XORG_OK"

if echo "$OPENBOX_OK" | grep -q "NO"; then
    echo ""
    echo "  ❌ Desktop packages NOT installed. Skipping hardening."
    echo "  Keeping APT available for debugging."
    
    # Unmount
    sudo umount -R "$MNT" 2>/dev/null || true
    sudo losetup -D 2>/dev/null || true
    exit 1
fi

echo "  ✓ All desktop packages verified!"

# Step 4: Apply security hardening (ONLY after successful install)
echo ""
echo "[4] Applying security hardening..."
sudo chroot "$MNT" bash -c '
export PATH=/usr/bin:/usr/sbin:/bin:/sbin

echo "  [4a] Removing APT package manager..."
apt-get clean 2>/dev/null || true
rm -f /usr/bin/apt-get /usr/bin/apt /usr/bin/apt-cache /usr/bin/apt-config
rm -f /usr/bin/apt-key /usr/bin/apt-mark /usr/bin/apt-cdrom
rm -rf /etc/apt/sources.list /etc/apt/sources.list.d/*
rm -rf /var/cache/apt /var/lib/apt/lists/*
echo "    ✓ APT removed"

echo "  [4b] Removing terminals & file managers..."
for bin in xfce4-terminal xterm lxterminal mate-terminal gnome-terminal \
           konsole rxvt urxvt sakura terminator tilix alacritty kitty \
           thunar pcmanfm nautilus nemo caja dolphin; do
    rm -f /usr/bin/$bin 2>/dev/null
done
echo "    ✓ Terminals & file managers removed"

echo "  [4c] Removing dangerous utilities..."
for bin in python python3 python3.12 perl gcc g++ cc c++ make cmake \
           wget curl ssh scp sftp nc ncat netcat telnet ftp \
           pip pip3 npm node gdb strace ltrace; do
    rm -f /usr/bin/$bin 2>/dev/null
    rm -f /usr/sbin/$bin 2>/dev/null
done
echo "    ✓ Dangerous utilities removed"

echo "  [4d] Blocking USB storage..."
mkdir -p /etc/modprobe.d
cat > /etc/modprobe.d/examos-block-usb-storage.conf << USBEOF
blacklist usb-storage
blacklist uas
USBEOF
echo "    ✓ USB storage blocked"

echo "  [4e] Configuring firewall..."
mkdir -p /etc/iptables
cat > /etc/iptables/rules.v4 << FWEOF
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT DROP [0:0]
-A INPUT -i lo -j ACCEPT
-A OUTPUT -o lo -j ACCEPT
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A OUTPUT -p udp --dport 67:68 -j ACCEPT
-A INPUT -p udp --sport 67:68 -j ACCEPT
-A OUTPUT -p udp --dport 53 -j ACCEPT
-A OUTPUT -p tcp --dport 53 -j ACCEPT
COMMIT
FWEOF
echo "    ✓ Firewall configured"

echo "  [4f] Blocking TTY switching..."
mkdir -p /etc/X11/xorg.conf.d
cat > /etc/X11/xorg.conf.d/99-examos-security.conf << XEOF
Section "ServerFlags"
    Option "DontZap" "true"
    Option "DontVTSwitch" "true"
EndSection
Section "InputClass"
    Identifier "Block SysRq"
    MatchIsKeyboard "on"
    Option "XkbOptions" "srvrkeys:none"
EndSection
XEOF
echo "    ✓ TTY switching blocked"

echo "  [4g] Restricting user permissions..."
chmod 700 /usr/bin/su 2>/dev/null || true
chmod 700 /usr/bin/chsh 2>/dev/null || true
mkdir -p /etc/sysctl.d
echo "kernel.dmesg_restrict = 1" > /etc/sysctl.d/99-examos.conf
echo "kernel.yama.ptrace_scope = 3" >> /etc/sysctl.d/99-examos.conf
echo "    ✓ Permissions restricted"

echo "  [4h] Process watchdog..."
cat > /usr/local/bin/examos-watchdog.sh << WEOF
#!/bin/bash
ALLOWED="openbox|tint2|chromium|pulseaudio|dbus|picom|dunst|lxpolkit|examos|Xorg|xinit|bash|startx|numlockx|feh|upower|at-spi|gpg-agent|dconf"
while true; do
    for pid in \$(pgrep -u 1000 2>/dev/null); do
        PNAME=\$(cat /proc/\$pid/comm 2>/dev/null)
        if [ -n "\$PNAME" ] && ! echo "\$PNAME" | grep -qE "\$ALLOWED"; then
            kill -9 \$pid 2>/dev/null
            logger "ExamOS: Killed unauthorized process \$PNAME (\$pid)"
        fi
    done
    sleep 5
done
WEOF
chmod +x /usr/local/bin/examos-watchdog.sh

cat > /etc/systemd/system/examos-watchdog.service << WSEOF
[Unit]
Description=ExamOS Process Watchdog
After=multi-user.target
[Service]
Type=simple
ExecStart=/usr/local/bin/examos-watchdog.sh
Restart=always
RestartSec=3
[Install]
WantedBy=multi-user.target
WSEOF
systemctl enable examos-watchdog.service 2>/dev/null || true
echo "    ✓ Process watchdog enabled"

echo ""
echo "  ✅ All security hardening applied!"
'

# Step 5: Final cleanup & convert
echo ""
echo "[5] Final cleanup..."
sudo rm -rf "$MNT/tmp/"* 2>/dev/null
echo "  Disk usage:"
df -h "$MNT" | tail -1

# Unmount
sudo umount "$MNT/run" 2>/dev/null
sudo umount "$MNT/tmp" 2>/dev/null
sudo umount "$MNT/sys" 2>/dev/null
sudo umount "$MNT/proc" 2>/dev/null
sudo umount "$MNT/dev/pts" 2>/dev/null
sudo umount "$MNT/dev" 2>/dev/null
sudo umount "$MNT"

# e2fsck before converting
echo ""
echo "[6] Running e2fsck..."
sudo e2fsck -f -y "${LOOP}p2" 2>&1 | tail -3

# Convert to VMDK
echo ""
echo "[7] Converting to VMDK..."
sudo losetup -d "$LOOP"
qemu-img convert -f raw -O vmdk "$RAW" "/mnt/d/SEB BRO/image/examos.vmdk" 2>&1
echo "  ✓ VMDK created"
ls -lh "/mnt/d/SEB BRO/image/examos.vmdk"

echo ""
echo "============================================"
echo "  ✅ ExamOS Secure Desktop Complete!"
echo "============================================"
echo "  VMDK ready at: D:\\SEB BRO\\image\\examos.vmdk"
echo "  Load in VMware Workstation Pro and test!"
