#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT="$ROOT/artifacts/p0"; mkdir -p "$OUT"
first_line() { "$@" 2>&1 | head -n1; }
{
  echo "timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "git_commit=$(git -C "$ROOT" rev-parse HEAD)"
  echo "host_kernel=$(uname -srvo)"
  echo "architecture=$(uname -m)"
  echo "cpu_count=$(nproc)"
  echo "ram_bytes=$(awk '/MemTotal/ {print $2*1024}' /proc/meminfo)"
  echo "free_storage_bytes=$(df -PB1 "$HOME" | awk 'NR==2 {print $4}')"
  grep -E '^(ID|VERSION_ID|PRETTY_NAME)=' /etc/os-release
} >"$OUT/build-info.txt"
{
  first_line git --version
  first_line mkosi --version
  first_line qemu-system-x86_64 --version
  first_line qemu-img --version
  first_line swtpm --version
  first_line tpm2_pcrread --version
  first_line sbsign --version
  first_line veritysetup --version
  first_line mksquashfs -version
} >"$OUT/tool-versions.txt"
{
  echo 'OVMF CODE candidates:'
  find /usr/share -type f -iname 'OVMF_CODE*.fd' -print 2>/dev/null | sort
  echo 'OVMF VARS candidates:'
  find /usr/share -type f -iname 'OVMF_VARS*.fd' -print 2>/dev/null | sort
  dpkg-query -W -f='package=${Package} version=${Version}\n' ovmf 2>/dev/null || true
} >"$OUT/ovmf-info.txt"
echo '[PASS] P0 environment evidence collected'
