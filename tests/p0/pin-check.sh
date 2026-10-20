#!/usr/bin/env bash
# Verify P0 package-source and toolchain pins are present and consistent.
set -euo pipefail

WORKSPACE="$(cd "$(dirname "$0")/../.." && pwd)"
LOCK="$WORKSPACE/image/p0/sources.lock"
TOOLS="$WORKSPACE/image/p0/toolchain.lock"
MKOSI="$WORKSPACE/image/p0/mkosi.conf"
CI="$WORKSPACE/.github/workflows/p0.yml"

fail() { echo "[P0-PIN] FAIL: $1" >&2; exit 1; }

[ -s "$LOCK" ] || fail "missing $LOCK"
[ -s "$TOOLS" ] || fail "missing $TOOLS"
[ -s "$MKOSI" ] || fail "missing $MKOSI"
[ -s "$CI" ] || fail "missing $CI"

snapshot="$(awk -F= '$1=="debian_snapshot" { sub(/\r$/, "", $2); print $2; exit }' "$LOCK")"
mirror="$(awk -F= '$1=="debian_mirror" { sub(/\r$/, "", $2); print $2; exit }' "$LOCK")"
runner="$(awk -F= '$1=="ci_runner_image" { sub(/\r$/, "", $2); print $2; exit }' "$TOOLS")"

[[ "$snapshot" =~ ^[0-9]{8}T[0-9]{6}Z$ ]] || fail "debian_snapshot is not a Debian snapshot timestamp"
[[ "$mirror" == *"$snapshot" ]] || fail "debian_mirror does not contain debian_snapshot"
awk -v expected="Mirror=$mirror" '{ sub(/\r$/, "") } $0 == expected { found=1 } END { exit !found }' "$MKOSI" || fail "image/p0/mkosi.conf Mirror= does not match sources.lock"
tr -d '\r' < "$CI" | grep -Fqx "    runs-on: $runner" || fail "P0 workflow is not pinned to $runner"
if tr -d '\r' < "$CI" | grep -Eq 'runs-on:[[:space:]]*ubuntu-latest'; then
    fail "P0 workflow still uses ubuntu-latest"
fi

echo "[P0-PIN] snapshot=$snapshot"
echo "[P0-PIN] mirror=$mirror"
echo "[P0-PIN] ci_runner_image=$runner"
echo "[P0-PIN] PASS"
