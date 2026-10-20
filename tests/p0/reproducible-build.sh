#!/usr/bin/env bash
# Two isolated clean builds from pinned inputs, then digest comparison.
#
# EXAMOS_P0_REPRO_MODE=native  — rebuild native C/C++ twice (not ENG-04 PASS)
# EXAMOS_P0_REPRO_MODE=image   — two mkosi P0 disk builds (release evidence)
set -euo pipefail

WORKSPACE="$(cd "$(dirname "$0")/../.." && pwd)"
MODE="${EXAMOS_P0_REPRO_MODE:-pins}"
OUT="${EXAMOS_P0_REPRO_OUT:-$WORKSPACE/artifacts/p0/reproducibility}"
LOCK="$WORKSPACE/image/p0/sources.lock"
mkdir -p "$OUT"

status=PASS
reason=""
block() { status=BLOCKED; reason="$1"; echo "[P0-REPRO] BLOCKED: $1" >&2; }
fail() { status=FAIL; reason="$1"; echo "[P0-REPRO] FAIL: $1" >&2; }

commit="$(git -C "$WORKSPACE" rev-parse HEAD 2>/dev/null || echo UNKNOWN)"
tree=CLEAN
if [ -n "$(git -C "$WORKSPACE" status --porcelain --untracked-files=all 2>/dev/null)" ]; then
    tree=DIRTY
fi

bash "$WORKSPACE/tests/p0/pin-check.sh" || fail "package/toolchain pins are inconsistent"

if [ "$tree" = DIRTY ] && [ "$status" = PASS ]; then
    block "source tree is DIRTY; two-build comparison is not release evidence"
fi

: >"$OUT/build-a.sha256"
: >"$OUT/build-b.sha256"

compare_pair() {
    local a="$1" b="$2" label="$3"
    local ha hb
    ha="$(sha256sum "$a" | awk '{ print $1 }')"
    hb="$(sha256sum "$b" | awk '{ print $1 }')"
    printf '%s %s\n' "$ha" "$label" >>"$OUT/build-a.sha256"
    printf '%s %s\n' "$hb" "$label" >>"$OUT/build-b.sha256"
    if [ "$ha" != "$hb" ]; then
        fail "$label digest mismatch ($ha vs $hb)"
        return 1
    fi
    echo "[P0-REPRO] $label matches $ha"
}

NATIVE_BINS=(server/examos-server agent/examos-agent kiosk/launcher/examos-kiosk-launcher proctoring/examos-proctor)

if [ "$status" != FAIL ] && [ "$MODE" = pins ]; then
    reason="package and toolchain pins verified; two isolated mkosi builds have not been compared"
    block "$reason"
elif [ "$status" != FAIL ] && [ "$MODE" = native ]; then
    if ! command -v make >/dev/null 2>&1; then
        block "make is not available"
    else
        A="$(mktemp -d "${TMPDIR:-/tmp}/examos-repro-a.XXXXXX")"
        B="$(mktemp -d "${TMPDIR:-/tmp}/examos-repro-b.XXXXXX")"
        cleanup() { rm -rf "$A" "$B"; }
        trap cleanup EXIT
        mkdir -p "$A/bin" "$B/bin"
        make -C "$WORKSPACE" clean >/dev/null 2>&1 || true
        if make -C "$WORKSPACE" all; then
            for rel in "${NATIVE_BINS[@]}"; do
                [ -f "$WORKSPACE/$rel" ] && cp -a "$WORKSPACE/$rel" "$A/bin/$(basename "$rel")"
            done
        else
            fail "native build A failed"
        fi
        if [ "$status" != FAIL ]; then
            make -C "$WORKSPACE" clean >/dev/null 2>&1 || true
            if make -C "$WORKSPACE" all; then
                for rel in "${NATIVE_BINS[@]}"; do
                    [ -f "$WORKSPACE/$rel" ] && cp -a "$WORKSPACE/$rel" "$B/bin/$(basename "$rel")"
                done
            else
                fail "native build B failed"
            fi
        fi
        if [ "$status" != FAIL ]; then
            matched=0
            for name in examos-server examos-agent examos-kiosk-launcher examos-proctor; do
                if [ -f "$A/bin/$name" ] && [ -f "$B/bin/$name" ]; then
                    compare_pair "$A/bin/$name" "$B/bin/$name" "$name" || true
                    matched=$((matched + 1))
                fi
            done
            if [ "$matched" -eq 0 ]; then
                block "native binaries were not produced; cannot compare isolated builds"
            elif [ "$status" = PASS ]; then
                reason="native binaries matched across two sequential clean rebuilds"
            fi
        fi
    fi
elif [ "$MODE" = image ]; then
    if [ "$tree" = DIRTY ]; then
        block "refusing image reproducibility on a dirty tree"
    elif ! command -v mkosi >/dev/null 2>&1; then
        block "mkosi is not available for isolated image builds"
    else
        A="$(mktemp -d "${TMPDIR:-/tmp}/examos-repro-img-a.XXXXXX")"
        B="$(mktemp -d "${TMPDIR:-/tmp}/examos-repro-img-b.XXXXXX")"
        cleanup() { rm -rf "$A" "$B"; }
        trap cleanup EXIT
        mirror="$(awk -F= '$1=="debian_mirror" { print $2; exit }' "$LOCK")"
        echo "[P0-REPRO] isolated mkosi builds using $mirror"
        if ! mkosi --force -C "$WORKSPACE/image/p0" \
                --cache-directory "$A/cache" --output-directory "$A/out" \
                --build-directory "$A/build" build; then
            block "image build A failed or snapshot mirror was unreachable"
        elif ! mkosi --force -C "$WORKSPACE/image/p0" \
                --cache-directory "$B/cache" --output-directory "$B/out" \
                --build-directory "$B/build" build; then
            block "image build B failed or snapshot mirror was unreachable"
        else
            img_a="$(find "$A/out" -type f \( -name '*.raw' -o -name 'examos-p0' \) | head -n1)"
            img_b="$(find "$B/out" -type f \( -name '*.raw' -o -name 'examos-p0' \) | head -n1)"
            if [ -z "$img_a" ] || [ -z "$img_b" ]; then
                fail "mkosi did not emit a disk image in both isolated output directories"
            else
                compare_pair "$img_a" "$img_b" "p0-disk"
                [ "$status" = PASS ] && reason="two isolated mkosi images produced matching SHA-256"
            fi
        fi
    fi
else
    fail "unknown EXAMOS_P0_REPRO_MODE=$MODE"
fi

python3 - "$OUT/report.json" "$status" "$reason" "$commit" "$tree" "$MODE" <<'PY'
import json, sys
out, status, reason, commit, tree, mode = sys.argv[1:7]
result = status
release_eligible = False
if tree == "DIRTY" and status != "FAIL":
    result = "BLOCKED"
    reason = reason or "dirty source tree"
if mode != "image" and status == "PASS":
    result = "BLOCKED"
    reason = (reason + "; " if reason else "") + \
        "ENG-04 requires two isolated mkosi image builds before PASS"
if result == "PASS" and mode == "image" and tree == "CLEAN":
    release_eligible = True
report = {
    "schema": "examos.p0.reproducibility.v1",
    "generated_at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "source_commit": commit,
    "source_tree_state": tree,
    "mode": mode,
    "result": result,
    "reason": reason,
    "release_eligible": release_eligible,
}
with open(out, "w", encoding="utf-8") as fh:
    json.dump(report, fh, indent=2)
    fh.write("\n")
print(json.dumps(report, indent=2))
sys.exit(0 if result == "PASS" else 2 if result == "BLOCKED" else 1)
PY
