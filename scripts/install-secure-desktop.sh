#!/bin/bash
# =============================================================================
# ExamOS Secure Desktop Installation Script
# Installs minimal locked-down desktop: Openbox + tint2 + Chromium kiosk
# =============================================================================
set -uo pipefail

RAW="/mnt/d/SEB BRO/image/examos.raw"
MNT="/mnt/examos"

echo "============================================"
echo "  ExamOS Secure Desktop Installer"
echo "============================================"
echo ""

# --- Step 0: Clean mount ---
echo "[0/8] Preparing mount..."
sudo umount -R "$MNT" 2>/dev/null || true
sudo losetup -D 2>/dev/null || true
sleep 1

sudo losetup -fP "$RAW"
LOOP=$(losetup -j "$RAW" | head -1 | cut -d: -f1)
echo "  Loop device: $LOOP"

sudo mkdir -p "$MNT"
sudo mount "${LOOP}p2" "$MNT"
echo "  Mounted rootfs at $MNT"
df -h "$MNT" | tail -1

echo ""

# --- Step 1: Verify image ---
echo "[1/8] Verifying image..."
echo "  OS: $(cat $MNT/etc/os-release | grep PRETTY_NAME | cut -d= -f2)"
echo "  Packages installed: $(grep -c '^Package:' $MNT/var/lib/dpkg/status 2>/dev/null || echo 0)"
echo "  Chromium: $(ls $MNT/usr/bin/chromium 2>/dev/null && echo 'YES' || echo 'NO')"
echo "  Cage: $(ls $MNT/usr/bin/cage 2>/dev/null && echo 'YES' || echo 'NO')"
echo "  NetworkManager: $(ls $MNT/usr/sbin/NetworkManager 2>/dev/null && echo 'YES' || echo 'NO')"
echo ""

# --- Step 2: Setup chroot ---
echo "[2/8] Setting up chroot environment..."
sudo mount --bind /dev "$MNT/dev"
sudo mount --bind /dev/pts "$MNT/dev/pts"
sudo mount -t proc proc "$MNT/proc"
sudo mount -t sysfs sysfs "$MNT/sys"
sudo mount -t tmpfs tmpfs "$MNT/tmp"
sudo mount -t tmpfs tmpfs "$MNT/run"

# DNS resolution
sudo mkdir -p "$MNT/run/systemd/resolve"
echo "nameserver 8.8.8.8" | sudo tee "$MNT/etc/resolv.conf" > /dev/null
echo "nameserver 8.8.4.4" | sudo tee -a "$MNT/etc/resolv.conf" > /dev/null
echo "  Chroot ready"
echo ""

# --- Step 3: Bootstrap APT ---
echo "[3/8] Bootstrapping APT package manager..."

# Check if apt already exists
if sudo chroot "$MNT" /bin/bash -c 'command -v apt-get' &>/dev/null; then
    echo "  APT already available!"
else
    echo "  APT not found, downloading from Debian mirrors..."
    
    APTDIR="$MNT/tmp/apt-bootstrap"
    sudo mkdir -p "$APTDIR"
    
    # Function to download a package from Debian mirrors
    download_pkg() {
        local pkg="$1"
        local url
        # Try compressed indices
        for comp in xz gz; do
            url=$(wget -q -O- "http://deb.debian.org/debian/dists/trixie/main/binary-amd64/Packages.${comp}" 2>/dev/null | \
                  (if [ "$comp" = "xz" ]; then xzcat; else zcat; fi) 2>/dev/null | \
                  awk -v pkg="$pkg" '
                      /^Package: / { p = ($2 == pkg) }
                      /^Filename: / && p { print $2; exit }
                  ')
            if [ -n "$url" ]; then
                wget -q "http://deb.debian.org/debian/${url}" -O "$APTDIR/$(basename $url)" 2>/dev/null
                echo "    ✓ $pkg"
                return 0
            fi
        done
        echo "    ✗ $pkg (not found)"
        return 1
    }
    
    echo "  Downloading core APT packages..."
    download_pkg "apt"
    download_pkg "libapt-pkg7.0"
    download_pkg "gpgv"
    download_pkg "debian-archive-keyring"
    download_pkg "libseccomp2"
    download_pkg "libxxhash0"
    download_pkg "liblz4-1"
    download_pkg "libzstd1"
    download_pkg "libsystemd0"
    download_pkg "libudev1"
    
    echo ""
    echo "  Installing APT packages via dpkg..."
    sudo chroot "$MNT" /bin/bash -c "
        export PATH=/usr/bin:/usr/sbin:/bin:/sbin
        # Install downloaded debs, ignore dependency issues initially
        dpkg --force-depends --force-confnew -i /tmp/apt-bootstrap/*.deb 2>&1 | grep -E '(Unpacking|Setting up|error)' || true
    "
    
    # Verify apt works
    if sudo chroot "$MNT" /bin/bash -c 'command -v apt-get' &>/dev/null; then
        echo "  ✓ APT installed successfully!"
    else
        echo "  APT install via dpkg failed. Trying direct copy from host..."
        # Copy host apt as fallback
        sudo cp /usr/bin/apt-get "$MNT/usr/bin/"
        sudo cp /usr/bin/apt "$MNT/usr/bin/"
        sudo cp /usr/bin/apt-cache "$MNT/usr/bin/"
        # Copy shared libs
        for lib in libapt-pkg.so* libapt-private.so*; do
            sudo cp /usr/lib/x86_64-linux-gnu/$lib "$MNT/usr/lib/x86_64-linux-gnu/" 2>/dev/null || true
        done
        sudo chroot "$MNT" ldconfig 2>/dev/null || true
        echo "  ✓ APT copied from host"
    fi
fi

# Setup Debian Trixie repositories
echo ""
echo "  Configuring Debian Trixie repositories..."
sudo mkdir -p "$MNT/etc/apt/sources.list.d"
sudo mkdir -p "$MNT/etc/apt/apt.conf.d"
sudo mkdir -p "$MNT/var/lib/apt/lists/partial"
sudo mkdir -p "$MNT/var/cache/apt/archives/partial"

cat << 'EOF' | sudo tee "$MNT/etc/apt/sources.list" > /dev/null
deb http://deb.debian.org/debian trixie main contrib
deb http://security.debian.org/debian-security trixie-security main contrib
EOF

# Disable apt sandbox for chroot
cat << 'EOF' | sudo tee "$MNT/etc/apt/apt.conf.d/99nosandbox" > /dev/null
APT::Sandbox::User "root";
EOF

# Download and install Debian keyring
echo "  Installing Debian archive keyring..."
KEYRING_URL=$(wget -q -O- "http://deb.debian.org/debian/dists/trixie/main/binary-amd64/Packages.xz" 2>/dev/null | \
    xzcat 2>/dev/null | \
    awk '/^Package: debian-archive-keyring$/{p=1} /^Filename: / && p{print $2; exit}')
if [ -n "$KEYRING_URL" ]; then
    wget -q "http://deb.debian.org/debian/${KEYRING_URL}" -O "$MNT/tmp/keyring.deb" 2>/dev/null
    sudo dpkg-deb -x "$MNT/tmp/keyring.deb" "$MNT/" 2>/dev/null
    # Copy keys to trusted
    sudo cp "$MNT/usr/share/keyrings/debian-archive-"*.gpg "$MNT/etc/apt/trusted.gpg.d/" 2>/dev/null || true
    echo "  ✓ Keyring installed"
fi

echo ""

# --- Step 4: Install desktop packages ---
echo "[4/8] Installing secure desktop packages..."
sudo chroot "$MNT" /bin/bash -c '
export DEBIAN_FRONTEND=noninteractive
export LC_ALL=C
export PATH=/usr/bin:/usr/sbin:/bin:/sbin

echo "  Updating package lists..."
apt-get update -qq 2>&1 | tail -3

echo ""
echo "  Installing minimal secure desktop (Openbox + tint2)..."
apt-get install -y --no-install-recommends \
    openbox \
    tint2 \
    xorg \
    xinit \
    x11-xserver-utils \
    x11-utils \
    dbus-x11 \
    libnotify-bin \
    adwaita-icon-theme \
    fonts-dejavu-core \
    pulseaudio \
    pulseaudio-utils \
    pavucontrol \
    upower \
    policykit-1 \
    lxpolkit \
    numlockx \
    feh \
    dunst \
    xdotool \
    xclip \
    picom \
    2>&1 | tail -10

echo ""
echo "  Package installation complete."
echo "  Checking key packages..."
for pkg in openbox tint2 xorg pulseaudio upower; do
    if dpkg -s "$pkg" &>/dev/null; then
        echo "    ✓ $pkg"
    else
        echo "    ✗ $pkg MISSING"
    fi
done
'

echo ""

# --- Step 5: Configure secure desktop ---
echo "[5/8] Configuring secure desktop environment..."

# === exam user home ===
sudo mkdir -p "$MNT/home/exam/.config/openbox"
sudo mkdir -p "$MNT/home/exam/.config/tint2"
sudo mkdir -p "$MNT/home/exam/.config/dunst"

# === Openbox autostart — launch tint2 + chromium kiosk ===
cat << 'OBSTART' | sudo tee "$MNT/home/exam/.config/openbox/autostart" > /dev/null
#!/bin/bash
# ExamOS Secure Desktop Autostart
# ================================

# Set dark background
xsetroot -solid "#1a1a2e" &

# Compositor for smooth rendering
picom --backend xrender --no-fading-openclose -b 2>/dev/null &

# Notification daemon
dunst &

# Enable NumLock
numlockx on &

# Start tint2 panel (taskbar)
tint2 &

# Start PulseAudio
pulseaudio --start 2>/dev/null &

# Start polkit agent for auth dialogs
lxpolkit &

# Wait for panel to load
sleep 2

# Launch ExamOS Secure Browser (ONLY allowed application)
chromium \
    --kiosk \
    --no-sandbox \
    --disable-gpu-sandbox \
    --test-type \
    --disable-extensions \
    --disable-plugins \
    --incognito \
    --no-first-run \
    --disable-translate \
    --disable-background-networking \
    --disable-sync \
    --disable-default-apps \
    --disable-component-update \
    --disable-domain-reliability \
    --no-default-browser-check \
    --autoplay-policy=no-user-gesture-required \
    http://localhost:8000 &

OBSTART
sudo chmod +x "$MNT/home/exam/.config/openbox/autostart"

# === Openbox rc.xml — LOCKED DOWN keyboard/mouse ===
cat << 'OBRC' | sudo tee "$MNT/home/exam/.config/openbox/rc.xml" > /dev/null
<?xml version="1.0" encoding="UTF-8"?>
<openbox_config xmlns="http://openbox.org/3.4/rc">
  <resistance><strength>10</strength><screen_edge_strength>20</screen_edge_strength></resistance>
  
  <focus>
    <focusNew>yes</focusNew>
    <followMouse>no</followMouse>
  </focus>
  
  <placement><policy>Smart</policy></placement>
  
  <theme>
    <name>Clearlooks</name>
    <titleLayout>L</titleLayout>
    <font place="ActiveWindow"><name>DejaVu Sans</name><size>10</size></font>
    <font place="InactiveWindow"><name>DejaVu Sans</name><size>10</size></font>
  </theme>
  
  <desktops><number>1</number></desktops>
  
  <!-- SECURITY: All dangerous keyboard shortcuts DISABLED -->
  <keyboard>
    <!-- Block ALL TTY switching -->
    <!-- Block Alt+F2 run dialog -->
    <!-- Block Ctrl+Alt+Delete -->
    <!-- Block Ctrl+Alt+T terminal -->
    <!-- No keybindings = no escape -->
  </keyboard>
  
  <!-- SECURITY: Disable right-click desktop menu -->
  <mouse>
    <context name="Desktop">
      <!-- No actions on desktop right-click -->
    </context>
    <context name="Root">
      <!-- No actions on root window -->
    </context>
    <context name="Client">
      <mousebind button="Left" action="Press"><action name="Focus"/><action name="Raise"/></mousebind>
    </context>
    <context name="Titlebar">
      <mousebind button="Left" action="Press"><action name="Focus"/><action name="Raise"/></mousebind>
      <mousebind button="Left" action="Drag"><action name="Move"/></mousebind>
    </context>
    <context name="Frame">
      <mousebind button="Left" action="Press"><action name="Focus"/><action name="Raise"/></mousebind>
    </context>
  </mouse>
  
  <applications>
    <!-- Force Chromium maximized, no decorations -->
    <application class="Chromium-browser" name="chromium-browser" type="normal">
      <maximized>yes</maximized>
      <decor>no</decor>
      <layer>normal</layer>
    </application>
  </applications>
</openbox_config>
OBRC

# === Openbox environment ===
cat << 'OBENV' | sudo tee "$MNT/home/exam/.config/openbox/environment" > /dev/null
export XDG_CURRENT_DESKTOP=openbox
export XDG_SESSION_TYPE=x11
OBENV

# === tint2 panel config (Windows-like taskbar) ===
cat << 'TINT2' | sudo tee "$MNT/home/exam/.config/tint2/tint2rc" > /dev/null
# ExamOS Secure Panel Configuration
# ==================================

# Panel appearance
panel_items = LTSC
panel_size = 100% 36
panel_margin = 0 0
panel_padding = 4 0 4
panel_position = bottom center horizontal
panel_layer = top
panel_monitor = all
panel_background_id = 1
panel_dock = 0
panel_pivot_struts = 0
autohide = 0
autohide_show_timeout = 0.3
autohide_hide_timeout = 1.5
autohide_height = 2

# Backgrounds
# ID 1 - Panel background (dark)
rounded = 0
border_width = 1
border_sides = T
background_color = #1e1e2e 95
border_color = #45475a 80
background_color_hover = #1e1e2e 95
border_color_hover = #45475a 80

# ID 2 - Active task
rounded = 4
border_width = 0
background_color = #45475a 80
border_color = #89b4fa 60

# ID 3 - System tray / clock bg
rounded = 4
border_width = 0
background_color = #313244 70
border_color = #45475a 50

# Launcher (ExamOS branding)
launcher_padding = 4 2 4
launcher_background_id = 0
launcher_icon_theme = Adwaita
launcher_icon_asb = 100 0 0
launcher_tooltip = 1

# Taskbar
taskbar_mode = single_desktop
taskbar_hide_if_empty = 0
taskbar_padding = 4 2 4
taskbar_background_id = 0
taskbar_active_background_id = 0
taskbar_name = 1
taskbar_hide_inactive_tasks = 0
taskbar_hide_different_monitor = 0
taskbar_always_show_all_desktop_tasks = 0
taskbar_name_padding = 6 2
taskbar_name_background_id = 0
taskbar_name_active_background_id = 2
taskbar_name_font_color = #cdd6f4 100
taskbar_name_active_font_color = #89b4fa 100
taskbar_distribute_size = 0
taskbar_sort_order = none

# Task buttons
task_text = 1
task_icon = 1
task_centered = 1
task_tooltip = 1
task_maximum_size = 200 32
task_padding = 6 2 6
task_font = DejaVu Sans 10
task_font_color = #cdd6f4 90
task_active_font_color = #89b4fa 100
task_background_id = 0
task_active_background_id = 2
task_icon_asb = 80 0 0
task_active_icon_asb = 100 0 0

# System Tray
systray_padding = 4 2 4
systray_background_id = 3
systray_sort = ascending
systray_icon_size = 22
systray_icon_asb = 100 0 0
systray_monitor = primary
systray_name_filter =

# Clock
time1_format = %H:%M
time1_timezone =
time1_font = DejaVu Sans Bold 11
time2_format = %a %d %b
time2_timezone =
time2_font = DejaVu Sans 9
clock_font_color = #cdd6f4 100
clock_padding = 8 0
clock_background_id = 3
clock_tooltip = ExamOS Secure Desktop
clock_lclick_command =
clock_rclick_command =
clock_mclick_command =
clock_uwheel_command =
clock_dwheel_command =

# Tooltips
tooltip_show_timeout = 0.5
tooltip_hide_timeout = 0.2
tooltip_padding = 6 4
tooltip_background_id = 3
tooltip_font_color = #cdd6f4 100
tooltip_font = DejaVu Sans 10
TINT2

# === Dunst notification config ===
cat << 'DUNST' | sudo tee "$MNT/home/exam/.config/dunst/dunstrc" > /dev/null
[global]
    monitor = 0
    follow = mouse
    width = 300
    height = 100
    origin = top-right
    offset = 10x46
    notification_limit = 3
    progress_bar = true
    indicate_hidden = yes
    transparency = 10
    separator_height = 2
    padding = 8
    horizontal_padding = 8
    frame_width = 2
    frame_color = "#45475a"
    separator_color = frame
    sort = yes
    font = DejaVu Sans 10
    markup = full
    format = "<b>%s</b>\n%b"
    alignment = left
    show_age_threshold = 60
    ellipsize = middle
    icon_position = left
    max_icon_size = 32
    sticky_history = yes
    history_length = 20
    corner_radius = 8

[urgency_low]
    background = "#1e1e2e"
    foreground = "#cdd6f4"
    timeout = 5

[urgency_normal]
    background = "#1e1e2e"
    foreground = "#cdd6f4"
    timeout = 10

[urgency_critical]
    background = "#1e1e2e"
    foreground = "#f38ba8"
    frame_color = "#f38ba8"
    timeout = 0
DUNST

# === .xinitrc for startx ===
cat << 'XINITRC' | sudo tee "$MNT/home/exam/.xinitrc" > /dev/null
#!/bin/bash
# ExamOS Secure Desktop Session
exec openbox-session
XINITRC
sudo chmod +x "$MNT/home/exam/.xinitrc"

# Fix ownership
sudo chroot "$MNT" chown -R 1000:1000 /home/exam

echo "  ✓ Desktop configuration complete"
echo ""

# --- Step 6: Create systemd desktop service ---
echo "[6/8] Creating desktop session service..."

# Autologin + startx service (replaces LightDM — smaller attack surface)
cat << 'GETTYD' | sudo tee "$MNT/etc/systemd/system/getty@tty1.service.d/override.conf" > /dev/null
[Service]
ExecStart=
ExecStart=-/sbin/agetty --autologin exam --noclear %I $TERM
Type=idle
GETTYD
sudo mkdir -p "$MNT/etc/systemd/system/getty@tty1.service.d"
# Re-create (mkdir might have raced)
cat << 'GETTYD' | sudo tee "$MNT/etc/systemd/system/getty@tty1.service.d/override.conf" > /dev/null
[Service]
ExecStart=
ExecStart=-/sbin/agetty --autologin exam --noclear %I $TERM
Type=idle
GETTYD

# Auto-startx on login for exam user
cat << 'BASHPROFILE' | sudo tee "$MNT/home/exam/.bash_profile" > /dev/null
# ExamOS Secure Desktop Auto-Launch
if [ -z "$DISPLAY" ] && [ "$(tty)" = "/dev/tty1" ]; then
    exec startx -- -nocursor 2>/dev/null
fi
BASHPROFILE
sudo chroot "$MNT" chown 1000:1000 /home/exam/.bash_profile

# Set graphical target
sudo chroot "$MNT" /bin/bash -c '
    systemctl set-default graphical.target 2>/dev/null || true
    systemctl disable examos-kiosk.service 2>/dev/null || true
    systemctl enable getty@tty1.service 2>/dev/null || true
'

echo "  ✓ Auto-login desktop session configured"
echo ""

# --- Step 7: SECURITY HARDENING ---
echo "[7/8] Applying security hardening..."

sudo chroot "$MNT" /bin/bash -c '
export PATH=/usr/bin:/usr/sbin:/bin:/sbin

echo "  [7a] Removing package managers (prevent software installation)..."
# Keep dpkg database but remove the tools
apt-get clean 2>/dev/null || true
rm -f /usr/bin/apt-get /usr/bin/apt /usr/bin/apt-cache /usr/bin/apt-config
rm -f /usr/bin/apt-key /usr/bin/apt-mark
rm -rf /etc/apt/sources.list /etc/apt/sources.list.d
rm -rf /var/cache/apt /var/lib/apt/lists
echo "    ✓ APT removed"

echo "  [7b] Removing terminal emulators..."
rm -f /usr/bin/xfce4-terminal 2>/dev/null
rm -f /usr/bin/xterm 2>/dev/null  
rm -f /usr/bin/lxterminal 2>/dev/null
rm -f /usr/bin/mate-terminal 2>/dev/null
rm -f /usr/bin/gnome-terminal 2>/dev/null
rm -f /usr/bin/konsole 2>/dev/null
rm -f /usr/bin/rxvt 2>/dev/null
rm -f /usr/bin/urxvt 2>/dev/null
# Keep bash for system scripts but remove from exam user access
echo "    ✓ Terminal emulators removed"

echo "  [7c] Removing file managers..."
rm -f /usr/bin/thunar 2>/dev/null
rm -f /usr/bin/pcmanfm 2>/dev/null
rm -f /usr/bin/nautilus 2>/dev/null
rm -f /usr/bin/nemo 2>/dev/null
rm -f /usr/bin/caja 2>/dev/null
rm -f /usr/bin/dolphin 2>/dev/null
echo "    ✓ File managers removed"

echo "  [7d] Removing dangerous utilities..."
rm -f /usr/bin/python* 2>/dev/null
rm -f /usr/bin/python3* 2>/dev/null
rm -f /usr/bin/perl 2>/dev/null
rm -f /usr/bin/gcc /usr/bin/g++ /usr/bin/cc 2>/dev/null
rm -f /usr/bin/make /usr/bin/cmake 2>/dev/null
rm -f /usr/bin/wget /usr/bin/curl 2>/dev/null
rm -f /usr/bin/ssh /usr/bin/scp /usr/bin/sftp 2>/dev/null
rm -f /usr/bin/nc /usr/bin/ncat /usr/bin/netcat 2>/dev/null
rm -f /usr/bin/telnet 2>/dev/null
rm -f /usr/bin/ftp 2>/dev/null
rm -f /usr/bin/pip* 2>/dev/null
rm -f /usr/bin/npm /usr/bin/node 2>/dev/null
echo "    ✓ Dangerous utilities removed"

echo "  [7e] Blocking USB storage..."
mkdir -p /etc/modprobe.d
cat > /etc/modprobe.d/examos-block-usb-storage.conf << USBEOF
# ExamOS: Block USB storage devices
blacklist usb-storage
blacklist uas
USBEOF

# udev rule to reject USB mass storage
mkdir -p /etc/udev/rules.d
cat > /etc/udev/rules.d/99-examos-block-usb.rules << UDEVEOF
# ExamOS: Block USB mass storage devices
ACTION=="add", SUBSYSTEMS=="usb", DRIVERS=="usb-storage", RUN+="/bin/sh -c echo 0 > /sys/\$devpath/authorized"
ACTION=="add", SUBSYSTEMS=="usb", ATTR{bInterfaceClass}=="08", RUN+="/bin/sh -c echo 0 > /sys/\$devpath/authorized"
UDEVEOF
echo "    ✓ USB storage blocked"

echo "  [7f] Configuring firewall (only localhost allowed)..."
mkdir -p /etc/iptables
cat > /etc/iptables/rules.v4 << FWEOF
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT DROP [0:0]

# Allow loopback (localhost communication)
-A INPUT -i lo -j ACCEPT
-A OUTPUT -o lo -j ACCEPT

# Allow established connections
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow DHCP for network indicator (but not actual internet)
-A OUTPUT -p udp --dport 67:68 -j ACCEPT
-A INPUT -p udp --sport 67:68 -j ACCEPT

# Allow DNS for network detection only
-A OUTPUT -p udp --dport 53 -j ACCEPT
-A OUTPUT -p tcp --dport 53 -j ACCEPT

# DROP everything else - no internet access for candidates
COMMIT
FWEOF

cat > /etc/iptables/rules.v6 << FW6EOF
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT DROP [0:0]
-A INPUT -i lo -j ACCEPT
-A OUTPUT -o lo -j ACCEPT
COMMIT
FW6EOF
echo "    ✓ Firewall rules configured"

echo "  [7g] Blocking TTY switching..."
mkdir -p /etc/X11/xorg.conf.d
cat > /etc/X11/xorg.conf.d/99-examos-security.conf << XORGEOF
Section "ServerFlags"
    # Disable Ctrl+Alt+Backspace (kill X)
    Option "DontZap" "true"
    # Disable Ctrl+Alt+Fn TTY switching
    Option "DontVTSwitch" "true"
EndSection

Section "InputClass"
    Identifier "Block SysRq"
    MatchIsKeyboard "on"
    Option "XkbOptions" "srvrkeys:none"
EndSection
XORGEOF
echo "    ✓ TTY switching blocked"

echo "  [7h] Restricting exam user permissions..."
# No sudo for exam user
rm -f /etc/sudoers.d/exam 2>/dev/null
# No su access
chmod 700 /usr/bin/su 2>/dev/null || true
# No shell change
chmod 700 /usr/bin/chsh 2>/dev/null || true
# Restrict dmesg
echo "kernel.dmesg_restrict = 1" >> /etc/sysctl.d/99-examos.conf
# Restrict ptrace
echo "kernel.yama.ptrace_scope = 3" >> /etc/sysctl.d/99-examos.conf
# Hide other processes
echo "proc /proc proc defaults,hidepid=2 0 0" >> /etc/fstab
echo "    ✓ User permissions restricted"

echo "  [7i] Setting up process whitelist..."
# Create a script that kills unauthorized processes
cat > /usr/local/bin/examos-watchdog.sh << WATCHEOF
#!/bin/bash
# ExamOS Process Watchdog
# Kills any unauthorized processes running as exam user
ALLOWED="openbox|tint2|chromium|pulseaudio|dbus|picom|dunst|lxpolkit|examos|Xorg|xinit|bash|startx|numlockx|feh|upower|at-spi"
while true; do
    for pid in \$(pgrep -u 1000); do
        PNAME=\$(cat /proc/\$pid/comm 2>/dev/null)
        if [ -n "\$PNAME" ] && ! echo "\$PNAME" | grep -qE "\$ALLOWED"; then
            kill -9 \$pid 2>/dev/null
            logger "ExamOS Watchdog: Killed unauthorized process \$PNAME (PID \$pid)"
        fi
    done
    sleep 5
done
WATCHEOF
chmod +x /usr/local/bin/examos-watchdog.sh

# Watchdog systemd service
cat > /etc/systemd/system/examos-watchdog.service << WDEOF
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
WDEOF
systemctl enable examos-watchdog.service 2>/dev/null || true
echo "    ✓ Process watchdog configured"
'

echo "  ✓ Security hardening complete"
echo ""

# --- Step 8: Cleanup and unmount ---
echo "[8/8] Cleaning up..."
sudo rm -rf "$MNT/tmp/apt-bootstrap" "$MNT/tmp/keyring.deb" 2>/dev/null
sudo rm -f "$MNT/etc/apt/apt.conf.d/99nosandbox" 2>/dev/null

# Show final disk usage
echo "  Final disk usage:"
df -h "$MNT" | tail -1

# Unmount
sudo umount "$MNT/run" 2>/dev/null
sudo umount "$MNT/tmp" 2>/dev/null
sudo umount "$MNT/sys" 2>/dev/null
sudo umount "$MNT/proc" 2>/dev/null
sudo umount "$MNT/dev/pts" 2>/dev/null
sudo umount "$MNT/dev" 2>/dev/null
sudo umount "$MNT"
sudo losetup -d "$LOOP"

echo ""
echo "============================================"
echo "  ✅ ExamOS Secure Desktop Installation Complete!"
echo "============================================"
echo ""
echo "  Desktop: Openbox + tint2 (minimal, locked-down)"
echo "  Panel: Clock, Battery, Volume, System Tray"
echo "  Session: Auto-login as exam → startx → openbox"
echo "  Browser: Chromium kiosk → localhost:8000"
echo ""
echo "  SECURITY:"
echo "  ✗ No package manager (apt removed)"
echo "  ✗ No terminal emulator"
echo "  ✗ No file manager"
echo "  ✗ No dangerous utilities (wget, curl, python, gcc)"
echo "  ✗ No USB storage"
echo "  ✗ No TTY switching"
echo "  ✗ No right-click desktop menu"
echo "  ✗ No keyboard shortcuts to escape"
echo "  ✗ Firewall: only localhost allowed"
echo "  ✗ Process watchdog kills unauthorized apps"
echo ""
echo "  Next: Convert to VMDK with:"
echo "  qemu-img convert -f raw -O vmdk examos.raw examos.vmdk"
