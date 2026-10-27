#!/usr/bin/env bash
set -e
PKG1=$(curl -s "http://deb.debian.org/debian/pool/main/o/openh264/" | grep -o 'libopenh264-8_[^"]*amd64.deb' | tail -1)
PKG2=$(curl -s "http://deb.debian.org/debian/pool/main/libj/libjpeg-turbo/" | grep -o 'libjpeg62-turbo_[^"]*amd64.deb' | tail -1)
PKG3=$(curl -s "http://deb.debian.org/debian/pool/main/h/harfbuzz/" | grep -o 'libharfbuzz-subset0_[^"]*amd64.deb' | tail -1)

echo "openh264: http://deb.debian.org/debian/pool/main/o/openh264/$PKG1"
echo "jpeg: http://deb.debian.org/debian/pool/main/libj/libjpeg-turbo/$PKG2"
echo "harfbuzz: http://deb.debian.org/debian/pool/main/h/harfbuzz/$PKG3"
