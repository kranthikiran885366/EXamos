#!/bin/bash
set -uo pipefail

MNT="/mnt/examos"

# Ensure mounted
if ! mountpoint -q "$MNT" 2>/dev/null; then
    sudo mkdir -p "$MNT"
    sudo mount /dev/loop0p2 "$MNT"
fi

# Bind mounts for chroot
sudo mount --bind /dev "$MNT/dev" 2>/dev/null || true
sudo mount --bind /dev/pts "$MNT/dev/pts" 2>/dev/null || true
sudo mount -t proc proc "$MNT/proc" 2>/dev/null || true
sudo mount -t sysfs sysfs "$MNT/sys" 2>/dev/null || true
sudo mount -t tmpfs tmpfs "$MNT/tmp" 2>/dev/null || true

# DNS
sudo cp /etc/resolv.conf "$MNT/etc/resolv.conf" 2>/dev/null || true

echo "=== Step 1: Bootstrap APT into image ==="
# Download apt and dependencies from Debian repos directly
# First check what we have
echo "Existing dpkg version:"
sudo chroot "$MNT" dpkg --version 2>/dev/null | head -1

# Use the host's apt to download debs for the target
# Create a temporary apt environment
STAGING="/tmp/apt-staging"
rm -rf "$STAGING"
mkdir -p "$STAGING"

echo ""
echo "Downloading apt and dependencies for Debian Trixie..."

# Download apt deb package directly from Debian mirrors
cd "$STAGING"

# Key packages we need
PACKAGES="apt libapt-pkg7.0 libgnutls30t64 libhogweed6t64 libnettle8t64 libp11-kit0 libtasn1-6 gpg gpgv libassuan9 libgpgme11t64 libgpg-error0 libnpth0t64 libksba8 libreadline8t64 debian-archive-keyring libseccomp2 libxxhash0 libzstd1 liblz4-1 libbz2-1.0 liblzma5 libgcrypt20 adduser"

# We'll use the host system to download the packages, then install them in chroot
echo "Using host apt to download target packages..."

# Create sources for Trixie
cat > /tmp/apt-trixie-sources.list << 'SRCEOF'
deb http://deb.debian.org/debian trixie main contrib non-free non-free-firmware
SRCEOF

# Download with host apt-get but for trixie
cd "$STAGING"
for pkg in apt libapt-pkg7.0 gpgv debian-archive-keyring; do
    echo "  Downloading $pkg..."
    apt-get download -o Dir::Etc::SourceList=/tmp/apt-trixie-sources.list \
        -o APT::Architecture=amd64 \
        "$pkg" 2>/dev/null || true
done

# Alternative approach: use debootstrap-style direct download from mirrors
echo ""
echo "Using direct mirror download approach..."
MIRROR="http://deb.debian.org/debian"
RELEASE="trixie"

# Get the packages we need via wget from the pool
download_deb() {
    local pkg="$1"
    local url
    url=$(wget -q -O- "${MIRROR}/dists/${RELEASE}/main/binary-amd64/Packages.gz" 2>/dev/null | \
        zcat 2>/dev/null | \
        awk -v pkg="$pkg" '
            /^Package: / { p = ($2 == pkg) }
            /^Filename: / && p { print $2; exit }
        ')
    if [ -n "$url" ]; then
        echo "  Downloading: $pkg -> $url"
        wget -q "${MIRROR}/${url}" -P "$STAGING/" 2>/dev/null
    else
        echo "  WARN: Could not find $pkg in mirror index"
    fi
}

# Core apt packages
for pkg in apt libapt-pkg7.0 gpgv debian-archive-keyring; do
    download_deb "$pkg"
done

echo ""
echo "Downloaded debs:"
ls -la "$STAGING/"*.deb 2>/dev/null || echo "No debs found via mirror method"

# Third approach: copy apt from host if same arch
echo ""
echo "=== Copying apt from host system ==="
# The host is Ubuntu - apt binary should work on Debian Trixie (same glibc)
# Let's just copy the apt binary and its libs
HOST_APT=$(which apt-get)
echo "Host apt-get: $HOST_APT"

# Better approach: install apt via dpkg using downloaded debs
# Or simplest: since the host IS a Debian-family system, copy apt directly
echo ""
echo "=== Using debootstrap to install apt ==="
# Check if debootstrap is available
if command -v debootstrap &>/dev/null; then
    echo "debootstrap found, using it to install apt into existing rootfs"
else
    echo "Installing debootstrap on host..."
    sudo apt-get install -y debootstrap 2>/dev/null
fi

# Simplest approach: Just install apt packages directly from the host into the chroot
echo ""
echo "=== Direct apt installation via dpkg ==="

# Copy the apt executable and configs from host
echo "Copying apt binaries from host to image..."
sudo cp /usr/bin/apt-get "$MNT/usr/bin/" 2>/dev/null || true
sudo cp /usr/bin/apt "$MNT/usr/bin/" 2>/dev/null || true
sudo cp /usr/bin/apt-cache "$MNT/usr/bin/" 2>/dev/null || true
sudo cp /usr/bin/apt-config "$MNT/usr/bin/" 2>/dev/null || true
sudo cp /usr/bin/apt-key "$MNT/usr/bin/" 2>/dev/null || true
sudo cp /usr/bin/apt-mark "$MNT/usr/bin/" 2>/dev/null || true

# Copy apt libs
echo "Copying apt libraries..."
sudo mkdir -p "$MNT/usr/lib/x86_64-linux-gnu/"
for lib in libapt-pkg.so* libapt-private.so*; do
    sudo cp /usr/lib/x86_64-linux-gnu/$lib "$MNT/usr/lib/x86_64-linux-gnu/" 2>/dev/null || true
done

# Copy additional dependencies
for lib in libgnutls.so* libhogweed.so* libnettle.so* libp11-kit.so* libtasn1.so* libxxhash.so* liblz4.so* libzstd.so* libunistring.so* libidn2.so*; do
    sudo cp /usr/lib/x86_64-linux-gnu/$lib "$MNT/usr/lib/x86_64-linux-gnu/" 2>/dev/null || true
done

# Copy gpgv for apt verification  
sudo cp /usr/bin/gpgv "$MNT/usr/bin/" 2>/dev/null || true
sudo cp /usr/bin/gpg "$MNT/usr/bin/" 2>/dev/null || true

# Copy apt configs
sudo mkdir -p "$MNT/etc/apt/apt.conf.d"
sudo mkdir -p "$MNT/etc/apt/sources.list.d"
sudo mkdir -p "$MNT/etc/apt/trusted.gpg.d"
sudo mkdir -p "$MNT/var/lib/apt/lists/partial"
sudo mkdir -p "$MNT/var/cache/apt/archives/partial"
sudo mkdir -p "$MNT/var/lib/dpkg/updates"
sudo mkdir -p "$MNT/var/log/apt"

# Copy Debian keyrings
sudo cp /usr/share/keyrings/debian-archive-*.gpg "$MNT/usr/share/keyrings/" 2>/dev/null || true
# Also copy Ubuntu keyrings as fallback
sudo cp /usr/share/keyrings/ubuntu-archive-*.gpg "$MNT/usr/share/keyrings/" 2>/dev/null || true

# Set up sources.list for Debian Trixie
cat << 'SRCEOF' | sudo tee "$MNT/etc/apt/sources.list" > /dev/null
deb http://deb.debian.org/debian trixie main contrib non-free non-free-firmware
deb http://security.debian.org/debian-security trixie-security main contrib non-free non-free-firmware
SRCEOF

# Also add signed-by trusted key
echo "Setting up GPG keyring for Debian..."
# Download and install Debian archive keyrings
wget -q -O /tmp/debian-keyring.deb "http://deb.debian.org/debian/pool/main/d/debian-archive-keyring/debian-archive-keyring_2025.1_all.deb" 2>/dev/null
if [ -f /tmp/debian-keyring.deb ]; then
    sudo dpkg-deb -x /tmp/debian-keyring.deb "$MNT/"
    echo "Debian keyring installed"
fi

echo ""
echo "Testing apt in chroot..."
sudo chroot "$MNT" /bin/bash -c 'export PATH=/usr/bin:/usr/sbin:/bin:/sbin; apt-get --version' 2>&1 | head -3

echo ""
echo "=== Step 2: Install XFCE4 Desktop ==="
sudo chroot "$MNT" /bin/bash -c '
export DEBIAN_FRONTEND=noninteractive
export LC_ALL=C
export PATH=/usr/bin:/usr/sbin:/bin:/sbin

echo "Running apt-get update..."
apt-get update -qq 2>&1 | tail -5

echo ""
echo "Installing XFCE4 desktop environment..."
apt-get install -y --no-install-recommends \
    xfce4 \
    xfce4-terminal \
    xfce4-panel \
    xfce4-power-manager \
    xfce4-pulseaudio-plugin \
    xfce4-battery-plugin \
    xfce4-notifyd \
    xfce4-taskmanager \
    lightdm \
    lightdm-gtk-greeter \
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
    2>&1 | tail -20

echo ""
echo "Checking installation results..."
dpkg -l xfce4 2>/dev/null | tail -1
dpkg -l lightdm 2>/dev/null | tail -1
dpkg -l xorg 2>/dev/null | tail -1
'

echo ""
echo "=== Step 3: Configure Desktop ==="
# LightDM autologin
sudo mkdir -p "$MNT/etc/lightdm/lightdm.conf.d"
cat << 'LDMEOF' | sudo tee "$MNT/etc/lightdm/lightdm.conf.d/50-autologin.conf" > /dev/null
[Seat:*]
autologin-user=exam
autologin-user-timeout=0
user-session=xfce
greeter-session=lightdm-gtk-greeter
LDMEOF

# LightDM GTK greeter branding
cat << 'GREETEOF' | sudo tee "$MNT/etc/lightdm/lightdm-gtk-greeter.conf" > /dev/null
[greeter]
background=#1a1a2e
theme-name=Adwaita-dark
icon-theme-name=Adwaita
font-name=DejaVu Sans 11
GREETEOF

# Enable LightDM + graphical target
sudo chroot "$MNT" /bin/bash -c '
systemctl enable lightdm.service 2>/dev/null || true
systemctl set-default graphical.target 2>/dev/null || true
systemctl disable examos-kiosk.service 2>/dev/null || true
'

# XFCE config for exam user
sudo mkdir -p "$MNT/home/exam/.config/autostart"
sudo mkdir -p "$MNT/home/exam/.config/xfce4/xfconf/xfce-perchannel-xml"

# ExamOS browser autostart
cat << 'ABEOF' | sudo tee "$MNT/home/exam/.config/autostart/examos-browser.desktop" > /dev/null
[Desktop Entry]
Type=Application
Name=ExamOS Secure Browser
Exec=chromium --kiosk --no-sandbox --disable-gpu-sandbox --test-type --disable-extensions --disable-plugins --incognito --no-first-run --disable-translate --disable-background-networking http://localhost:8000
Hidden=false
NoDisplay=false
X-GNOME-Autostart-enabled=true
ABEOF

# XFCE panel config
cat << 'PANELEOF' | sudo tee "$MNT/home/exam/.config/xfce4/xfconf/xfce-perchannel-xml/xfce4-panel.xml" > /dev/null
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

# Dark theme
cat << 'XSETEOF' | sudo tee "$MNT/home/exam/.config/xfce4/xfconf/xfce-perchannel-xml/xsettings.xml" > /dev/null
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

# Desktop background (solid dark color)
cat << 'DSKEOF' | sudo tee "$MNT/home/exam/.config/xfce4/xfconf/xfce-perchannel-xml/xfce4-desktop.xml" > /dev/null
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

# .xprofile
cat << 'XPEOF' | sudo tee "$MNT/home/exam/.xprofile" > /dev/null
#!/bin/bash
numlockx on 2>/dev/null &
XPEOF
sudo chmod +x "$MNT/home/exam/.xprofile"

# Fix ownership
sudo chroot "$MNT" chown -R 1000:1000 /home/exam

echo ""
echo "=== Step 4: Disk usage after install ==="
df -h "$MNT"

echo ""
echo "=== DONE ==="
