#!/usr/bin/env bash
# Verify P0 package-source and toolchain pins are present and consistent.
set -euo pipefail

WORKSPACE="$(cd "$(dirname "$0")/../.." && pwd)"
LOCK="$WORKSPACE/image/p0/sources.lock"
TOOLS="$WORKSPACE/image/p0/toolchain.lock"
MKOSI="$WORKSPACE/image/p0/mkosi.conf"
CI="$WORKSPACE/.github/workflows/p0.yml"
PIN_RESULT=""
if [ "$#" -gt 0 ]; then
    [ "$#" -eq 2 ] && [ "$1" = "--record" ] || {
        echo "Usage: $0 [--record <run-bound-result.json>]" >&2
        exit 2
    }
    PIN_RESULT="$2"
fi

fail() { echo "[P0-PIN] FAIL: $1" >&2; exit 1; }

[ -s "$LOCK" ] || fail "missing $LOCK"
[ -s "$TOOLS" ] || fail "missing $TOOLS"
[ -s "$MKOSI" ] || fail "missing $MKOSI"
[ -s "$CI" ] || fail "missing $CI"

snapshot="$(awk -F= '$1=="debian_snapshot" { sub(/\r$/, "", $2); print $2; exit }' "$LOCK")"
mirror="$(awk -F= '$1=="debian_mirror" { sub(/\r$/, "", $2); print $2; exit }' "$LOCK")"
security_mirror="$(awk -F= '$1=="debian_security_mirror" { sub(/\r$/, "", $2); print $2; exit }' "$LOCK")"
repart_seed="$(awk -F= '$1=="repart_seed" { sub(/\r$/, "", $2); print $2; exit }' "$LOCK")"
runner="$(awk -F= '$1=="ci_runner_image" { sub(/\r$/, "", $2); print $2; exit }' "$TOOLS")"

[[ "$snapshot" =~ ^[0-9]{8}T[0-9]{6}Z$ ]] || fail "debian_snapshot is not a Debian snapshot timestamp"
[[ "$mirror" == "https://snapshot.debian.org" ]] || fail "debian_mirror must be the snapshot service base URL"
[[ "$security_mirror" == "$mirror/archive/debian-security/$snapshot" ]] || fail "debian_security_mirror does not match the locked snapshot"
[[ "$repart_seed" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$ ]] || fail "repart_seed is not a valid UUID"
awk -v expected="Snapshot=$snapshot" '{ sub(/\r$/, "") } $0 == expected { found=1 } END { exit !found }' "$MKOSI" || fail "image/p0/mkosi.conf Snapshot= does not match sources.lock"
awk -v expected="Seed=$repart_seed" '{ sub(/\r$/, "") } $0 == expected { found=1 } END { exit !found }' "$MKOSI" || fail "image/p0/mkosi.conf Seed= does not match sources.lock"
if tr -d '\r' < "$MKOSI" | grep -Eq '^[[:space:]]*Mirror[[:space:]]*='; then
    fail "image/p0/mkosi.conf must let mkosi derive snapshot repository paths from Snapshot="
fi
tr -d '\r' < "$CI" | grep -Fqx "    runs-on: $runner" || fail "P0 workflow is not pinned to $runner"
if tr -d '\r' < "$CI" | grep -Eq 'runs-on:[[:space:]]*ubuntu-latest'; then
    fail "P0 workflow still uses ubuntu-latest"
fi

echo "[P0-PIN] snapshot=$snapshot"
echo "[P0-PIN] mirror=$mirror"
echo "[P0-PIN] security_mirror=$security_mirror"
echo "[P0-PIN] repart_seed=$repart_seed"
echo "[P0-PIN] ci_runner_image=$runner"
if [ -n "$PIN_RESULT" ]; then
    source "$WORKSPACE/scripts/examos-lib.sh"
    ARTIFACT_DIR="${EXAMOS_P0_ARTIFACT_DIR:-}"
    examos_p0_validate_run_dir "$WORKSPACE" "$ARTIFACT_DIR" || fail "run-bound P0 evidence directory is invalid"
    [ "$(realpath -m -- "$PIN_RESULT")" = "$PIN_RESULT" ] || fail "pin result path must be canonical"
    [ "$(dirname "$PIN_RESULT")" = "$ARTIFACT_DIR" ] || fail "pin result must be written inside this evidence run"
    [ ! -e "$PIN_RESULT" ] && [ ! -L "$PIN_RESULT" ] && \
        [ ! -e "$PIN_RESULT.tmp" ] && [ ! -L "$PIN_RESULT.tmp" ] ||
        fail "refusing to overwrite pinned-input evidence"
    source_commit="$(git -C "$WORKSPACE" rev-parse HEAD)" || fail "unable to bind pin result to a source commit"
    source_state="$(python3 "$WORKSPACE/scripts/source-state.py" "$WORKSPACE" --format json)" || fail "unable to read source state"
    source_tree_state="$(printf '%s\n' "$source_state" | jq -er '.state')" || fail "source state report is invalid"
    [ "$source_tree_state" = CLEAN ] || fail "release pins cannot be recorded for a dirty source tree"
    jq -n --arg commit "$source_commit" --arg generated_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
        --arg snapshot "$snapshot" --arg seed "$repart_seed" --arg runner "$runner" \
        --arg sources_sha256 "$(sha256sum "$LOCK" | cut -d' ' -f1)" \
        --arg toolchain_sha256 "$(sha256sum "$TOOLS" | cut -d' ' -f1)" \
        --arg mkosi_config_sha256 "$(sha256sum "$MKOSI" | cut -d' ' -f1)" \
        --arg workflow_sha256 "$(sha256sum "$CI" | cut -d' ' -f1)" \
        '{schema:"examos.p0.pinned-inputs.v1",status:"PASS",generated_at:$generated_at,
          source_commit:$commit,source_tree_state:"CLEAN",debian_snapshot:$snapshot,
          repart_seed:$seed,ci_runner_image:$runner,
          sources_lock_sha256:$sources_sha256,toolchain_lock_sha256:$toolchain_sha256,
          mkosi_config_sha256:$mkosi_config_sha256,workflow_sha256:$workflow_sha256}' \
        > "$PIN_RESULT.tmp" || fail "unable to serialize pinned-input evidence"
    mv -- "$PIN_RESULT.tmp" "$PIN_RESULT" || fail "unable to publish pinned-input evidence"
fi
echo "[P0-PIN] PASS"
