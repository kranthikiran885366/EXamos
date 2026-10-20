#!/usr/bin/env bash
# =============================================================================
# ExamOS P0 — Disk Image Forensics Analyzer
# tests/p0/image-forensics.sh
# Analyzes the built examos.raw for GPT, partitions, filesystems, and integrity
# =============================================================================
set -euo pipefail

WORKSPACE="$(cd "$(dirname "$0")/../.." && pwd)"
ARTIFACT_DIR="${EXAMOS_P0_ARTIFACT_DIR:?Run scripts/p0.sh or set EXAMOS_P0_ARTIFACT_DIR to a unique evidence run directory}"
source "$WORKSPACE/scripts/examos-lib.sh"
examos_p0_load_format "$WORKSPACE" || { echo '[FORENSICS] BLOCKED: invalid canonical partition contract' >&2; exit 2; }
examos_p0_validate_run_dir "$WORKSPACE" "$ARTIFACT_DIR" || { echo '[FORENSICS] BLOCKED: invalid P0 evidence run directory' >&2; exit 2; }
IMAGE_RELATIVE=""
[ -s "$ARTIFACT_DIR/image-path.txt" ] && IFS= read -r IMAGE_RELATIVE < "$ARTIFACT_DIR/image-path.txt"
EXPECTED_IMAGE_RELATIVE="$(realpath --relative-to="$WORKSPACE" "$ARTIFACT_DIR/examos-p0.raw")"
[ "$IMAGE_RELATIVE" = "$EXPECTED_IMAGE_RELATIVE" ] || { echo '[FORENSICS] FAIL: image is not bound to this evidence run' >&2; exit 1; }
IMAGE="$WORKSPACE/$IMAGE_RELATIVE"
[ -f "$IMAGE" ] && [ -s "$IMAGE" ] && [ ! -L "$IMAGE" ] || { echo '[FORENSICS] FAIL: bound disk image is missing or invalid' >&2; exit 1; }

ENT_DIR="$ARTIFACT_DIR/enterprise"
mkdir -p "$ENT_DIR"

echo "============================================================"
echo "ExamOS P0 — Disk Image Forensics"
echo "============================================================"
echo "[FORENSICS] Analyzing: $IMAGE"

CHECKS=0
PASSED=0

# --- 1. Image exists and size ---
IMAGE_BYTES=$(stat -c%s "$IMAGE" 2>/dev/null || echo 0)
IMAGE_HUMAN=$(du -sh "$IMAGE" | cut -f1)
echo "[FORENSICS] Image size: $IMAGE_HUMAN ($IMAGE_BYTES bytes)"
CHECKS=$((CHECKS + 1))
if [ "$IMAGE_BYTES" -gt 0 ]; then
    echo "[FORENSICS] Non-empty image check: PASS"
    PASSED=$((PASSED + 1))
    SIZE_STATUS="PASS"
else
    echo "[FORENSICS] Non-empty image check: FAIL ($IMAGE_HUMAN)"
    SIZE_STATUS="FAIL"
fi

# --- 2. GPT partition table ---
CHECKS=$((CHECKS + 1))
GPT_DUMP=$(sfdisk --dump "$IMAGE" 2>/dev/null || true)
if echo "$GPT_DUMP" | grep -qi 'label:\s*gpt'; then
    echo "[FORENSICS] GPT partition table: PASS"
    PASSED=$((PASSED + 1))
    GPT_STATUS="PASS"
else
    echo "[FORENSICS] GPT partition table: FAIL"
    GPT_STATUS="FAIL"
fi

# --- 3. ESP partition ---
CHECKS=$((CHECKS + 1))
ESP_FOUND="false"
if echo "$GPT_DUMP" | grep -Eiq "type=${EXAMOS_P0_ESP_TYPE_GUID}"; then
    echo "[FORENSICS] EFI System Partition: PASS"
    PASSED=$((PASSED + 1))
    ESP_STATUS="PASS"
    ESP_FOUND="true"
else
    echo "[FORENSICS] EFI System Partition: FAIL (not found in GPT)"
    ESP_STATUS="FAIL"
fi

# --- 4. Root partition ---
CHECKS=$((CHECKS + 1))
ROOT_FOUND="false"
if echo "$GPT_DUMP" | grep -Eiq "type=${EXAMOS_P0_ROOT_TYPE_GUID}"; then
    echo "[FORENSICS] Linux root x86-64 partition: PASS"
    PASSED=$((PASSED + 1))
    ROOT_STATUS="PASS"
    ROOT_FOUND="true"
else
    echo "[FORENSICS] Linux root partition: FAIL"
    ROOT_STATUS="FAIL"
fi

# --- 5. SHA-256 integrity ---
CHECKS=$((CHECKS + 1))
COMPUTED_HASH=$(sha256sum "$IMAGE" | cut -d' ' -f1)
RECORDED_HASH=""
if [ -f "$ARTIFACT_DIR/image.sha256" ]; then
    RECORDED_HASH=$(cut -d' ' -f1 < "$ARTIFACT_DIR/image.sha256")
fi
if [ -n "$RECORDED_HASH" ] && [ "$COMPUTED_HASH" = "$RECORDED_HASH" ]; then
    echo "[FORENSICS] SHA-256 integrity match: PASS"
    PASSED=$((PASSED + 1))
    HASH_STATUS="PASS"
else
    echo "[FORENSICS] SHA-256 integrity: FAIL (computed=$COMPUTED_HASH recorded=$RECORDED_HASH)"
    HASH_STATUS="FAIL"
fi

# --- 6. Companion artifacts ---
CHECKS=$((CHECKS + 1))
COMPANIONS=0
VMLINUZ="false"; INITRD="false"; EFI="false"
for f in "$WORKSPACE/image/examos.vmlinuz"; do
    if [ -f "$f" ]; then VMLINUZ="true"; COMPANIONS=$((COMPANIONS + 1)); fi
done
for f in "$WORKSPACE/image/examos.initrd"; do
    if [ -f "$f" ]; then INITRD="true"; COMPANIONS=$((COMPANIONS + 1)); fi
done
for f in "$WORKSPACE/image/examos.efi" "$WORKSPACE/image/examos.raw.efi"; do
    if [ -f "$f" ]; then EFI="true"; COMPANIONS=$((COMPANIONS + 1)); break; fi
done
if [ "$COMPANIONS" -ge 2 ]; then
    echo "[FORENSICS] Companion artifacts (vmlinuz=$VMLINUZ initrd=$INITRD efi=$EFI): PASS"
    PASSED=$((PASSED + 1))
    ARTIFACT_STATUS="PASS"
else
    echo "[FORENSICS] Companion artifacts: WARN (only $COMPANIONS found)"
    ARTIFACT_STATUS="WARN"
fi

# --- Partition detail dump ---
echo ""
echo "[FORENSICS] Partition layout:"
sfdisk -l "$IMAGE" 2>/dev/null | grep -E '^\/' || sfdisk --dump "$IMAGE" 2>/dev/null | grep -v '^$' | head -20 || true

# --- Generate JSON ---
FORENSICS_STATUS=PASS
for required_status in "$SIZE_STATUS" "$GPT_STATUS" "$ESP_STATUS" "$ROOT_STATUS" "$HASH_STATUS"; do
    [ "$required_status" = PASS ] || FORENSICS_STATUS=FAIL
done
cat > "$ENT_DIR/image-forensics.json" <<JSONEOF
{
  "schema": "examos.p0.forensics.v1",
  "source_commit": "$(git -C "$WORKSPACE" rev-parse HEAD)",
  "source_tree_state": "$(python3 "$WORKSPACE/scripts/source-state.py" "$WORKSPACE" --format json | python3 -c 'import json,sys; print(json.load(sys.stdin)["state"])')",
  "artifact_path": "$IMAGE_RELATIVE",
  "artifact_sha256": "$COMPUTED_HASH",
  "image_size_bytes": $IMAGE_BYTES,
  "image_size_human": "$IMAGE_HUMAN",
  "sha256_computed": "$COMPUTED_HASH",
  "sha256_recorded": "$RECORDED_HASH",
  "gpt_table": "$GPT_STATUS",
  "esp_partition": "$ESP_STATUS",
  "root_partition": "$ROOT_STATUS",
  "hash_integrity": "$HASH_STATUS",
  "companion_artifacts": {"vmlinuz": $VMLINUZ, "initrd": $INITRD, "efi": $EFI, "status": "$ARTIFACT_STATUS"},
  "checks": $CHECKS,
  "passed": $PASSED,
  "status": "$FORENSICS_STATUS"
}
JSONEOF

echo ""
echo "============================================================"
echo "[FORENSICS] Result: $PASSED/$CHECKS passed"
echo "============================================================"
[ "$FORENSICS_STATUS" = PASS ]
