#!/usr/bin/env bash
# Preserve a disposable P3 attestation-suite output directory as an immutable
# evidence package under artifacts/p3/evidence-packages/ without overwriting
# the default artifacts/p3 gate outputs.
set -euo pipefail

WORKSPACE="$(cd "$(dirname "$0")/.." && pwd)"
SRC="${1:-}"

if [ -z "$SRC" ] || [ ! -d "$SRC" ]; then
    echo "Usage: $0 <source-directory>" >&2
    echo "Example: $0 /tmp/examos-p3-results.BToS4h" >&2
    exit 1
fi

BASENAME="$(basename "$SRC")"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
PKG="$WORKSPACE/artifacts/p3/evidence-packages/${BASENAME}-${STAMP}"

REQUIRED=(
    attestation-pass.json
    attestation-suite-results.json
    replay-test.json
    revocation-test.json
    runtime-tpm.json
    test-ledger.log
)

mkdir -p "$PKG"
for f in "${REQUIRED[@]}"; do
    if [ ! -f "$SRC/$f" ]; then
        echo "FATAL: missing required file: $SRC/$f" >&2
        exit 1
    fi
    cp --no-preserve=timestamps "$SRC/$f" "$PKG/$f"
done

(
    cd "$PKG"
    sha256sum "${REQUIRED[@]}" > MANIFEST.sha256
)

git -C "$WORKSPACE" rev-parse HEAD > "$PKG/SOURCE_COMMIT.txt" 2>/dev/null || echo UNKNOWN > "$PKG/SOURCE_COMMIT.txt"
if [ -n "$(git -C "$WORKSPACE" status --porcelain 2>/dev/null)" ]; then
    echo DIRTY > "$PKG/SOURCE_TREE_STATE.txt"
else
    echo CLEAN > "$PKG/SOURCE_TREE_STATE.txt"
fi
date -u +%Y-%m-%dT%H:%M:%SZ > "$PKG/PRESERVED_AT.txt"
printf '%s\n' "$SRC" > "$PKG/SOURCE_PATH.txt"

cat > "$PKG/README.txt" <<EOF
ExamOS P3 attestation-suite evidence package (read-only copy).
Source: $SRC
Preserved: $(cat "$PKG/PRESERVED_AT.txt")
Repository commit at preserve time: $(cat "$PKG/SOURCE_COMMIT.txt")
Tree state: $(cat "$PKG/SOURCE_TREE_STATE.txt")

This package does not replace artifacts/p3/*. Re-run verification with:
  sha256sum -c MANIFEST.sha256
EOF

echo "=== P3 evidence preserved ==="
echo "Package: $PKG"
echo "--- MANIFEST.sha256 ---"
cat "$PKG/MANIFEST.sha256"
echo "--- attestation-suite-results.json ---"
cat "$PKG/attestation-suite-results.json"
