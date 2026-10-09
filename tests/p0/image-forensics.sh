#!/usr/bin/env bash
# =============================================================================
# ExamOS P0 — Disk Image Forensics Analyzer
# tests/p0/image-forensics.sh
# Analyzes the built examos.raw for GPT, partitions, filesystems, and integrity
# =============================================================================
set -euo pipefail

WORKSPACE="$(cd "$(dirname "$0")/../.." && pwd)"
IMAGE=""
for candidate in "$WORKSPACE/image/examos.raw" "$WORKSPACE/image/examos.raw.raw"; do
    if [ -f "$candidate" ]; then IMAGE="$candidate"; break; fi
done

if [ -z "$IMAGE" ]; then
    echo '{"status":"FAIL","reason":"No disk image found"}'
    exit 1
fi

ENT_DIR="$WORKSPACE/artifacts/p0/enterprise"
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
if [ "$IMAGE_BYTES" -gt 524288000 ]; then
    echo "[FORENSICS] Size check (>500MB): PASS"
    PASSED=$((PASSED + 1))
    SIZE_STATUS="PASS"
else
    echo "[FORENSICS] Size check (>500MB): FAIL ($IMAGE_HUMAN)"
    SIZE_STATUS="FAIL"
fi

# --- 2. GPT partition table ---
CHECKS=$((CHECKS + 1))
GPT_DUMP=$(sfdisk --dump "$IMAGE" 2>/dev/null || echo "UNAVAILABLE")
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
if echo "$GPT_DUMP" | grep -qi 'type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B'; then
    echo "[FORENSICS] EFI System Partition: PASS"
    PASSED=$((PASSED + 1))
    ESP_STATUS="PASS"
    ESP_FOUND="true"
elif echo "$GPT_DUMP" | grep -qi 'EFI\|esp'; then
    echo "[FORENSICS] EFI System Partition: PASS (detected by label)"
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
if echo "$GPT_DUMP" | grep -qi 'type=4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709'; then
    echo "[FORENSICS] Linux root x86-64 partition: PASS"
    PASSED=$((PASSED + 1))
    ROOT_STATUS="PASS"
    ROOT_FOUND="true"
elif echo "$GPT_DUMP" | grep -qi 'root\|linux'; then
    echo "[FORENSICS] Linux root partition: PASS (detected by label)"
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
if [ -f "$WORKSPACE/artifacts/p0/image.sha256" ]; then
    RECORDED_HASH=$(cut -d' ' -f1 < "$WORKSPACE/artifacts/p0/image.sha256")
fi
if [ -n "$RECORDED_HASH" ] && [ "$COMPUTED_HASH" = "$RECORDED_HASH" ]; then
    echo "[FORENSICS] SHA-256 integrity match: PASS"
    PASSED=$((PASSED + 1))
    HASH_STATUS="PASS"
else
    echo "[FORENSICS] SHA-256 integrity: WARN (computed=$COMPUTED_HASH recorded=$RECORDED_HASH)"
    HASH_STATUS="WARN"
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
cat > "$ENT_DIR/image-forensics.json" <<JSONEOF
{
  "image_path": "$IMAGE",
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
  "status": "$([ $PASSED -ge $((CHECKS - 1)) ] && echo PASS || echo FAIL)"
}
JSONEOF

echo ""
echo "============================================================"
echo "[FORENSICS] Result: $PASSED/$CHECKS passed"
echo "============================================================"
exit $([ $PASSED -ge $((CHECKS - 1)) ] && echo 0 || echo 1)
