#!/bin/bash
set -uo pipefail

LOOP="/dev/loop0"
PART="${LOOP}p2"
MNT="/mnt/examos"

echo "=== Step 1: e2fsck ==="
sudo e2fsck -f -y "$PART" || true

echo ""
echo "=== Step 2: resize2fs ==="
sudo resize2fs "$PART"
echo "Filesystem resized successfully!"

echo ""
echo "=== Step 3: Mount rootfs ==="
sudo mkdir -p "$MNT"
sudo mount "$PART" "$MNT"
sudo mount "${LOOP}p1" "$MNT/boot/efi" 2>/dev/null || true

# Bind mount for chroot
sudo mount --bind /dev "$MNT/dev"
sudo mount --bind /dev/pts "$MNT/dev/pts"
sudo mount -t proc proc "$MNT/proc"
sudo mount -t sysfs sysfs "$MNT/sys"
sudo mount -t tmpfs tmpfs "$MNT/tmp"

# DNS for apt
sudo cp /etc/resolv.conf "$MNT/etc/resolv.conf" 2>/dev/null || true

echo ""
echo "=== Step 4: Install XFCE4 Desktop Environment ==="
sudo chroot "$MNT" /bin/bash -c '
export DEBIAN_FRONTEND=noninteractive
export LC_ALL=C

echo "Updating package lists..."
apt-get update -qq

echo ""
echo "Installing XFCE4 desktop + utilities..."
apt-get install -y --no-install-recommends \
    xfce4 \
    xfce4-terminal \
    xfce4-panel \
    xfce4-power-manager \
    xfce4-pulseaudio-plugin \
    xfce4-battery-plugin \
    xfce4-notifyd \
    xfce4-taskmanager \
    xfce4-screensaver \
    lightdm \
    lightdm-gtk-greeter \
    network-manager \
    network-manager-gnome \
    nm-tray \
    pavucontrol \
    pulseaudio \
    dbus-x11 \
    xorg \
    xinit \
    x11-xserver-utils \
    adwaita-icon-theme \
    gnome-themes-extra \
    fonts-dejavu-core \
    numlockx \
    2>&1 | tail -5

echo ""
echo "Desktop packages installed!"

# Configure LightDM autologin for exam user
echo "Configuring LightDM autologin..."
mkdir -p /etc/lightdm/lightdm.conf.d
cat > /etc/lightdm/lightdm.conf.d/50-autologin.conf << LDMEOF
[Seat:*]
autologin-user=exam
autologin-user-timeout=0
user-session=xfce
greeter-session=lightdm-gtk-greeter
LDMEOF

# Configure LightDM GTK greeter for ExamOS branding
cat > /etc/lightdm/lightdm-gtk-greeter.conf << GREETEOF
[greeter]
background=#1a1a2e
theme-name=Adwaita-dark
icon-theme-name=Adwaita
font-name=DejaVu Sans 11
GREETEOF

# Enable LightDM
systemctl enable lightdm.service 2>/dev/null || true

# Set graphical.target as default
systemctl set-default graphical.target 2>/dev/null || true

# Disable old kiosk service to avoid conflicts
systemctl disable examos-kiosk.service 2>/dev/null || true

# Create exam user .xprofile for auto-launching ExamOS browser
mkdir -p /home/exam
cat > /home/exam/.xprofile << XPEOF
#!/bin/bash
# Start ExamOS services indicator
numlockx on 2>/dev/null &
XPEOF
chmod +x /home/exam/.xprofile
chown -R 1000:1000 /home/exam

# Create XFCE4 autostart for ExamOS browser
mkdir -p /home/exam/.config/autostart
cat > /home/exam/.config/autostart/examos-browser.desktop << ABEOF
[Desktop Entry]
Type=Application
Name=ExamOS Secure Browser
Exec=chromium --kiosk --no-sandbox --disable-gpu-sandbox --test-type --disable-extensions --disable-plugins --incognito --no-first-run --disable-translate --disable-background-networking http://localhost:8000
Hidden=false
NoDisplay=false
X-GNOME-Autostart-enabled=true
ABEOF
chown -R 1000:1000 /home/exam/.config

# XFCE4 panel configuration for taskbar
mkdir -p /home/exam/.config/xfce4/xfconf/xfce-perchannel-xml
cat > /home/exam/.config/xfce4/xfconf/xfce-perchannel-xml/xfce4-panel.xml << PANELEOF
<?xml version="1.0" encoding="UTF-8"?>
<channel name="xfce4-panel" version="1.0">
  <property name="configver" type="int" value="2"/>
  <property name="panels" type="array">
    <value type="int" value="1"/>
    <property name="panel-1" type="empty">
      <property name="position" type="string" value="p=8;x=0;y=0"/>
      <property name="length" type="uint" value="100"/>
      <property name="position-locked" type="bool" value="true"/>
      <property name="size" type="uint" value="30"/>
      <property name="plugin-ids" type="array">
        <value type="int" value="1"/>
        <value type="int" value="2"/>
        <value type="int" value="3"/>
        <value type="int" value="4"/>
        <value type="int" value="5"/>
        <value type="int" value="6"/>
        <value type="int" value="7"/>
        <value type="int" value="8"/>
      </property>
    </property>
  </property>
  <property name="plugins" type="empty">
    <property name="plugin-1" type="string" value="applicationsmenu"/>
    <property name="plugin-2" type="string" value="tasklist"/>
    <property name="plugin-3" type="string" value="separator">
      <property name="expand" type="bool" value="true"/>
    </property>
    <property name="plugin-4" type="string" value="pulseaudio"/>
    <property name="plugin-5" type="string" value="power-manager-plugin"/>
    <property name="plugin-6" type="string" value="notification-plugin"/>
    <property name="plugin-7" type="string" value="clock"/>
    <property name="plugin-8" type="string" value="actions"/>
  </property>
</channel>
PANELEOF
chown -R 1000:1000 /home/exam/.config/xfce4

# Set dark theme for XFCE
mkdir -p /home/exam/.config/xfce4/xfconf/xfce-perchannel-xml
cat > /home/exam/.config/xfce4/xfconf/xfce-perchannel-xml/xsettings.xml << XSETEOF
<?xml version="1.0" encoding="UTF-8"?>
<channel name="xsettings" version="1.0">
  <property name="Net" type="empty">
    <property name="ThemeName" type="string" value="Adwaita-dark"/>
    <property name="IconThemeName" type="string" value="Adwaita"/>
  </property>
  <property name="Gtk" type="empty">
    <property name="FontName" type="string" value="DejaVu Sans 11"/>
    <property name="CursorThemeName" type="string" value="Adwaita"/>
  </property>
</channel>
XSETEOF
chown -R 1000:1000 /home/exam/.config

# Set desktop wallpaper to solid dark color
mkdir -p /home/exam/.config/xfce4/xfconf/xfce-perchannel-xml
cat > /home/exam/.config/xfce4/xfconf/xfce-perchannel-xml/xfce4-desktop.xml << DSKEOF
<?xml version="1.0" encoding="UTF-8"?>
<channel name="xfce4-desktop" version="1.0">
  <property name="backdrop" type="empty">
    <property name="screen0" type="empty">
      <property name="monitorVirtual-1" type="empty">
        <property name="workspace0" type="empty">
          <property name="color-style" type="int" value="0"/>
          <property name="image-style" type="int" value="0"/>
          <property name="rgba1" type="array">
            <value type="double" value="0.101961"/>
            <value type="double" value="0.101961"/>
            <value type="double" value="0.180392"/>
            <value type="double" value="1.000000"/>
          </property>
        </property>
      </property>
    </property>
  </property>
</channel>
DSKEOF
chown -R 1000:1000 /home/exam/.config

echo ""
echo "=== Desktop environment configuration complete! ==="
echo "  - XFCE4 desktop installed"
echo "  - LightDM autologin configured for exam user"
echo "  - Dark theme (Adwaita-dark) set"
echo "  - Taskbar: App Menu | Task List | Volume | Battery | Notifications | Clock | Actions"
echo "  - ExamOS browser auto-launches in kiosk mode"
echo "  - graphical.target set as default boot target"
'

echo ""
echo "=== Step 5: Cleanup and unmount ==="
sudo umount "$MNT/tmp" 2>/dev/null
sudo umount "$MNT/sys" 2>/dev/null
sudo umount "$MNT/proc" 2>/dev/null
sudo umount "$MNT/dev/pts" 2>/dev/null
sudo umount "$MNT/dev" 2>/dev/null
sudo umount "$MNT/boot/efi" 2>/dev/null
sudo umount "$MNT"

echo ""
echo "=== DONE! Desktop environment installed into ExamOS image ==="
