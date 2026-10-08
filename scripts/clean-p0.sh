#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

for path in \
  "$ROOT/artifacts/p0" \
  "$ROOT/cache" \
  "$ROOT/output" \
  "$ROOT/build" \
  "$ROOT/image/output"; do
  if [[ -e "$path" ]]; then
    rm -rf "$path"
  fi
done

mkdir -p "$ROOT/artifacts/p0" "$ROOT/cache/packages" "$ROOT/cache/mkosi" "$ROOT/cache/qemu"
printf '%s\n' "[clean-p0] Generated P0 artifacts and caches cleaned."
