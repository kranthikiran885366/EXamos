#!/bin/bash
set -euo pipefail

RAW="/mnt/d/SEB BRO/image/examos.raw"
VMDK="/mnt/d/SEB BRO/image/examos.vmdk"
MNT="/mnt/examos"

echo "=== [1/6] Mounting ExamOS RootFS ==="
sudo umount -R "$MNT" 2>/dev/null || true
sudo losetup -D 2>/dev/null || true
sleep 1

sudo losetup -fP "$RAW"
LOOP=$(losetup -j "$RAW" | head -n 1 | cut -d: -f1)
echo "Attached loop: $LOOP"

sudo mkdir -p "$MNT"
sudo mount "${LOOP}p2" "$MNT"

# Chroot mounts
sudo mount --bind /dev "$MNT/dev"
sudo mount --bind /dev/pts "$MNT/dev/pts"
sudo mount -t proc proc "$MNT/proc"
sudo mount -t sysfs sysfs "$MNT/sys"
sudo mount -t tmpfs tmpfs "$MNT/tmp"
sudo mount -t tmpfs tmpfs "$MNT/run"
echo "nameserver 8.8.8.8" | sudo tee "$MNT/etc/resolv.conf" > /dev/null

echo "=== [2/6] Installing GUI Desktop Packages ==="
sudo chroot "$MNT" /bin/bash << 'EOF'
export DEBIAN_FRONTEND=noninteractive
export LC_ALL=C
export PATH=/usr/bin:/usr/sbin:/bin:/sbin

apt-get update -qq

# Install essential desktop components
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
    numlockx \
    feh \
    dunst \
    picom

echo "Package check:"
for pkg in openbox tint2 xorg xinit pulseaudio upower numlockx dunst picom; do
    if dpkg -s "$pkg" >/dev/null 2>&1; then
        echo "  [OK] $pkg"
    else
        echo "  [FAILED] $pkg"
    fi
done
EOF

echo "=== [3/6] Setting Up Secure Desktop Session & Config ==="
# Create user exam directories
sudo mkdir -p "$MNT/home/exam/.config/openbox"
sudo mkdir -p "$MNT/home/exam/.config/tint2"
sudo mkdir -p "$MNT/home/exam/.config/dunst"

# Openbox autostart
cat << 'OBSTART' | sudo tee "$MNT/home/exam/.config/openbox/autostart" > /dev/null
#!/bin/bash
# ExamOS Desktop Autostart

# Solid dark background
xsetroot -solid "#1a1a2e" &

# Compositor for smooth rendering
picom --backend xrender --no-fading-openclose -b 2>/dev/null &

# Notification daemon
dunst &

# Turn on NumLock
numlockx on 2>/dev/null &

# Start taskbar panel (shows battery, volume, network, clock)
tint2 &

# Start sound daemon
pulseaudio --start 2>/dev/null &

# Wait for panel initialization
sleep 1

# Launch ExamOS Secure Browser in locked Kiosk mode
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

# Openbox rc.xml (Locking shortcuts and right-click)
cat << 'OBRC' | sudo tee "$MNT/home/exam/.config/openbox/rc.xml" > /dev/null
<?xml version="1.0" encoding="UTF-8"?>
<openbox_config xmlns="http://openbox.org/3.4/rc">
  <resistance><strength>10</strength><screen_edge_strength>20</screen_edge_strength></resistance>
  <focus><focusNew>yes</focusNew><followMouse>no</followMouse></focus>
  <placement><policy>Smart</policy></placement>
  <theme>
    <name>Clearlooks</name>
    <titleLayout>L</titleLayout>
    <font place="ActiveWindow"><name>DejaVu Sans</name><size>10</size></font>
    <font place="InactiveWindow"><name>DejaVu Sans</name><size>10</size></font>
  </theme>
  <desktops><number>1</number></desktops>
  <keyboard></keyboard>
  <mouse>
    <context name="Desktop"></context>
    <context name="Root"></context>
    <context name="Client">
      <mousebind button="Left" action="Press"><action name="Focus"/><action name="Raise"/></mousebind>
    </context>
  </mouse>
  <applications>
    <application class="Chromium-browser" name="chromium-browser" type="normal">
      <maximized>yes</maximized>
      <decor>no</decor>
      <layer>normal</layer>
    </application>
  </applications>
</openbox_config>
OBRC

# tint2 config (Windows/Linux styled taskbar with telemetry & indicators)
cat << 'TINT2' | sudo tee "$MNT/home/exam/.config/tint2/tint2rc" > /dev/null
# ExamOS Panel Configuration
panel_items = LTSC
panel_size = 100% 36
panel_margin = 0 0
panel_padding = 4 0 4
panel_position = bottom center horizontal
panel_layer = top
panel_monitor = all
panel_background_id = 1
panel_dock = 0
autohide = 0

# Colors & Backgrounds
rounded = 0
border_width = 1
border_sides = T
background_color = #1e1e2e 95
border_color = #45475a 80

rounded = 4
border_width = 0
background_color = #45475a 80
border_color = #89b4fa 60

rounded = 4
border_width = 0
background_color = #313244 70
border_color = #45475a 50

# Launcher / Branding
launcher_padding = 4 2 4
launcher_background_id = 0
launcher_icon_theme = Adwaita
launcher_tooltip = 1

# Taskbar
taskbar_mode = single_desktop
taskbar_hide_if_empty = 0
taskbar_padding = 4 2 4
taskbar_background_id = 0
taskbar_active_background_id = 0
taskbar_name = 1
taskbar_name_padding = 6 2
taskbar_name_background_id = 0
taskbar_name_active_background_id = 2
taskbar_name_font_color = #cdd6f4 100
taskbar_name_active_font_color = #89b4fa 100

# Task button
task_text = 1
task_icon = 1
task_centered = 1
task_tooltip = 1
task_maximum_size = 220 32
task_padding = 6 2 6
task_font = DejaVu Sans 10
task_font_color = #cdd6f4 90
task_active_font_color = #89b4fa 100
task_background_id = 0
task_active_background_id = 2

# System Tray (Network, Volume, Battery status)
systray_padding = 4 2 4
systray_background_id = 3
systray_sort = ascending
systray_icon_size = 22
systray_icon_asb = 100 0 0
systray_monitor = primary

# Clock
time1_format = %H:%M
time1_font = DejaVu Sans Bold 11
time2_format = %a %d %b
time2_font = DejaVu Sans 9
clock_font_color = #cdd6f4 100
clock_padding = 8 0
clock_background_id = 3
clock_tooltip = ExamOS Secure Desktop
TINT2

# .xinitrc
cat << 'XINITRC' | sudo tee "$MNT/home/exam/.xinitrc" > /dev/null
#!/bin/bash
exec openbox-session
XINITRC
sudo chmod +x "$MNT/home/exam/.xinitrc"

# .bash_profile auto-startx on tty1
cat << 'BASHPROF' | sudo tee "$MNT/home/exam/.bash_profile" > /dev/null
if [ -z "$DISPLAY" ] && [ "$(tty)" = "/dev/tty1" ]; then
    exec startx -- -nocursor 2>/dev/null
fi
BASHPROF

# Ensure proper permissions
sudo chroot "$MNT" chown -R 1000:1000 /home/exam

# Override getty@tty1 for exam autologin
sudo mkdir -p "$MNT/etc/systemd/system/getty@tty1.service.d"
cat << 'GETTYD' | sudo tee "$MNT/etc/systemd/system/getty@tty1.service.d/override.conf" > /dev/null
[Service]
ExecStart=
ExecStart=-/sbin/agetty --autologin exam --noclear %I $TERM
Type=idle
GETTYD

# Set graphical default and disable legacy kiosk service
sudo chroot "$MNT" /bin/bash << 'EOF'
systemctl set-default graphical.target 2>/dev/null || true
systemctl disable examos-kiosk.service 2>/dev/null || true
EOF

echo "=== [4/6] Applying ExamOS Security Hardening ==="
sudo chroot "$MNT" /bin/bash << 'EOF'
export PATH=/usr/bin:/usr/sbin:/bin:/sbin

# Remove package managers
apt-get clean 2>/dev/null || true
rm -f /usr/bin/apt-get /usr/bin/apt /usr/bin/apt-cache /usr/bin/apt-config /usr/bin/apt-key /usr/bin/apt-mark
rm -rf /etc/apt/sources.list /etc/apt/sources.list.d/* /var/cache/apt /var/lib/apt/lists/*

# Remove terminal emulators & file managers
for bin in xfce4-terminal xterm lxterminal mate-terminal gnome-terminal konsole rxvt urxvt sakura terminator tilix alacritty kitty thunar pcmanfm nautilus nemo caja dolphin; do
    rm -f /usr/bin/$bin 2>/dev/null
done

# Remove dangerous dev/network utilities
for bin in python python3 python3.12 perl gcc g++ cc c++ make cmake wget curl ssh scp sftp nc ncat netcat telnet ftp pip pip3 npm node gdb strace ltrace; do
    rm -f /usr/bin/$bin 2>/dev/null
    rm -f /usr/sbin/$bin 2>/dev/null
done

# Block USB storage
mkdir -p /etc/modprobe.d
cat > /etc/modprobe.d/examos-block-usb-storage.conf << USBEOF
blacklist usb-storage
blacklist uas
USBEOF

# Block TTY switching in Xorg
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

# User permissions & kernel protection
chmod 700 /usr/bin/su 2>/dev/null || true
chmod 700 /usr/bin/chsh 2>/dev/null || true
mkdir -p /etc/sysctl.d
echo "kernel.dmesg_restrict = 1" > /etc/sysctl.d/99-examos.conf
echo "kernel.yama.ptrace_scope = 3" >> /etc/sysctl.d/99-examos.conf

# Process Watchdog
cat > /usr/local/bin/examos-watchdog.sh << 'WEOF'
#!/bin/bash
ALLOWED="openbox|tint2|chromium|pulseaudio|dbus|picom|dunst|examos|Xorg|xinit|bash|startx|numlockx|feh|upower|at-spi|dconf"
while true; do
    for pid in $(pgrep -u 1000 2>/dev/null); do
        PNAME=$(cat /proc/$pid/comm 2>/dev/null)
        if [ -n "$PNAME" ] && ! echo "$PNAME" | grep -qE "$ALLOWED"; then
            kill -9 $pid 2>/dev/null
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
EOF

echo "=== [5/6] Unmounting and Verifying Filesystem ==="
sudo umount "$MNT/run" 2>/dev/null || true
sudo umount "$MNT/tmp" 2>/dev/null || true
sudo umount "$MNT/sys" 2>/dev/null || true
sudo umount "$MNT/proc" 2>/dev/null || true
sudo umount "$MNT/dev/pts" 2>/dev/null || true
sudo umount "$MNT/dev" 2>/dev/null || true
sudo umount "$MNT" 2>/dev/null || true

echo "Running filesystem check..."
sudo e2fsck -f -y "${LOOP}p2" || true

sudo losetup -d "$LOOP"

echo "=== [6/6] Converting to VMware VMDK ==="
qemu-img convert -f raw -O vmdk "$RAW" "$VMDK"
echo "VMDK Generation complete!"
ls -lh "$VMDK"
