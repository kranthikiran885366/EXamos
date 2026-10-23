#!/usr/bin/env bash
set -euo pipefail

WORKSPACE=$(cd "$(dirname "$0")/../.." && pwd)
ARTIFACT_DIR="${EXAMOS_P1_ARTIFACT_DIR:-$WORKSPACE/artifacts/p1}"
mkdir -p "$ARTIFACT_DIR"

echo "=== [P1-PERF] Measuring Performance & Artifact Baselines ==="

PERF_FILE="$ARTIFACT_DIR/performance.txt"
echo "=== ExamOS P1 Performance Metrics ===" > "$PERF_FILE"
date -u +"Timestamp: %Y-%m-%dT%H:%M:%SZ" >> "$PERF_FILE"

IMAGE_FILE=""
for cand in "$WORKSPACE/image/examos.raw.raw" "$WORKSPACE/image/examos.raw"; do
    if [ -f "$cand" ]; then
        IMAGE_FILE="$cand"
        break
    fi
done

if [ -z "$IMAGE_FILE" ]; then
    echo "[P1-PERF] BLOCKED: no built disk image is available for measurement" >&2
    exit 2
fi

BOOT_RESULT="$ARTIFACT_DIR/boot-result.json"
if [ ! -s "$BOOT_RESULT" ]; then
    echo "[P1-PERF] BLOCKED: this run has no structured boot measurement" >&2
    exit 2
fi

python3 - "$IMAGE_FILE" "$BOOT_RESULT" "$PERF_FILE" <<'PY'
import hashlib, json, pathlib, sys
image, boot_result, output = map(pathlib.Path, sys.argv[1:])
try:
    result = json.loads(boot_result.read_text(encoding="utf-8"))
except (OSError, json.JSONDecodeError) as exc:
    print(f"[P1-PERF] FAIL: invalid boot measurement: {exc}", file=sys.stderr)
    raise SystemExit(1)
digest = hashlib.sha256(image.read_bytes()).hexdigest()
if result.get("result") != "PASS" or result.get("image_sha256") != digest:
    print("[P1-PERF] FAIL: boot evidence failed or belongs to a different image", file=sys.stderr)
    raise SystemExit(1)
elapsed = result.get("elapsed_ms")
if not isinstance(elapsed, int) or elapsed <= 0:
    print("[P1-PERF] FAIL: boot duration is missing or invalid", file=sys.stderr)
    raise SystemExit(1)
with output.open("a", encoding="utf-8") as report:
    report.write(f"Image Path: {image.resolve()}\n")
    report.write(f"Image SHA-256: {digest}\n")
    report.write(f"Image Size Bytes: {image.stat().st_size}\n")
    report.write(f"Measured QEMU Boot Elapsed Ms: {elapsed}\n")
    report.write(f"QEMU Acceleration: {result.get('acceleration', 'UNKNOWN')}\n")
print(f"[P1-PERF] PASS: image and boot timing bound to SHA-256 {digest}")
PY
