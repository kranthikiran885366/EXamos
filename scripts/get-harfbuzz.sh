#!/usr/bin/env bash
set -e
PKG=$(curl -s "http://deb.debian.org/debian/pool/main/h/harfbuzz/" | grep -o 'libharfbuzz0b_[^"]*amd64.deb' | tail -1)
echo "Matching harfbuzz: http://deb.debian.org/debian/pool/main/h/harfbuzz/$PKG"
