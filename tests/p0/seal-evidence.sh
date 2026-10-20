#!/usr/bin/env bash
# Seal an already-generated P0 evidence directory without modifying artifacts.
set -euo pipefail

WORKSPACE="$(cd "$(dirname "$0")/../.." && pwd)"
EVIDENCE_DIR="${1:-}"

fail() {
    echo "[P0-SEAL] FATAL: $*" >&2
    exit 1
}

[ -n "$EVIDENCE_DIR" ] || fail "Usage: $0 <artifacts/evidence/p0-*>"
EVIDENCE_DIR="$(realpath -e "$EVIDENCE_DIR")" || fail "Evidence directory does not exist"
EXPECTED_ROOT="$WORKSPACE/artifacts/evidence/"
case "$EVIDENCE_DIR/" in
    "$EXPECTED_ROOT"p0-*/) ;;
    *) fail "Evidence directory must be directly below artifacts/evidence/p0-*" ;;
esac

for required in image-path.txt image.sha256 build-result.json \
                boot-result.json iso-build-result.json iso-boot-result.json \
                examos-p0.iso iso.sha256; do
    [ -s "$EVIDENCE_DIR/$required" ] || fail "Missing required evidence file: $required"
done

sha256sum --check "$EVIDENCE_DIR/image.sha256"
sha256sum --check "$EVIDENCE_DIR/iso.sha256"

{
    echo "schema=examos-p0-evidence-v1"
    echo "sealed_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "source_commit=$(git -C "$WORKSPACE" rev-parse HEAD)"
    if [ -n "$(git -C "$WORKSPACE" status --porcelain --untracked-files=all)" ]; then
        echo "source_tree_state=DIRTY"
    else
        echo "source_tree_state=CLEAN"
    fi
    echo "mkosi=$(mkosi --version | head -n1)"
    echo "qemu=$(qemu-system-x86_64 --version | head -n1)"
    echo "ovmf=$(source "$WORKSPACE/scripts/examos-lib.sh"; examos_find_ovmf_code)"
} > "$EVIDENCE_DIR/PROVENANCE.txt"

TMP_MANIFEST="$EVIDENCE_DIR/.MANIFEST.sha256.tmp"
trap 'rm -f "$TMP_MANIFEST"' EXIT
(
    cd "$EVIDENCE_DIR"
    find . -maxdepth 1 -type f ! -name 'MANIFEST.sha256' ! -name '.MANIFEST.sha256.tmp' \
        -printf '%f\0' | LC_ALL=C sort -z | xargs -0r sha256sum
) > "$TMP_MANIFEST"
mv "$TMP_MANIFEST" "$EVIDENCE_DIR/MANIFEST.sha256"

(
    cd "$EVIDENCE_DIR"
    sha256sum -c MANIFEST.sha256
)
echo "[P0-SEAL] PASS: $EVIDENCE_DIR"
