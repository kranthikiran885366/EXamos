#!/usr/bin/env bash
# Collect, hash, and verify supplied release boot-chain artifacts.  This never
# creates keys, signatures, measurements, or a PASS from missing inputs.
set -euo pipefail

OUT_DIR="${EXAMOS_BOOT_CHAIN_EVIDENCE_DIR:-/tmp/examos-boot-chain-evidence-$(date -u +%Y%m%dT%H%M%SZ)}"
UKI="${EXAMOS_RELEASE_UKI:-}"
DB_CERT="${EXAMOS_RELEASE_DB_CERT:-}"
ROOTFS="${EXAMOS_RELEASE_ROOTFS:-}"
VERITY_TREE="${EXAMOS_RELEASE_VERITY_TREE:-}"
VERITY_ROOT_HASH="${EXAMOS_RELEASE_VERITY_ROOT_HASH:-}"
EVENT_LOG="${EXAMOS_RELEASE_EVENT_LOG:-}"

mkdir -p "$OUT_DIR"
REPORT="$OUT_DIR/boot-chain-evidence.json"
LOG="$OUT_DIR/verification.log"
declare -a BLOCKED=() FAILED=() PASSED=()
block() { BLOCKED+=("$1"); printf '[BLOCKED] %s\n' "$1" | tee -a "$LOG" >&2; }
fail() { FAILED+=("$1"); printf '[FAIL] %s\n' "$1" | tee -a "$LOG" >&2; }
pass() { PASSED+=("$1"); printf '[PASS] %s\n' "$1" | tee -a "$LOG"; }

for required in sha256sum python3; do command -v "$required" >/dev/null || { echo "Missing $required" >&2; exit 2; }; done

if [[ -z "$UKI" || ! -f "$UKI" ]]; then
  block "EXAMOS_RELEASE_UKI is not a readable release UKI"
elif [[ -z "$DB_CERT" || ! -f "$DB_CERT" ]]; then
  block "EXAMOS_RELEASE_DB_CERT is not a readable approved DB certificate"
elif ! command -v sbverify >/dev/null; then
  block "sbverify is unavailable"
elif sbverify --cert "$DB_CERT" "$UKI" >>"$LOG" 2>&1; then
  pass "UKI signature verifies against supplied DB certificate"
else
  fail "UKI signature does not verify against supplied DB certificate"
fi

if [[ -n "$UKI" && -f "$UKI" ]]; then
  if command -v objcopy >/dev/null && objcopy --dump-section .cmdline="$OUT_DIR/uki.cmdline" "$UKI" >>"$LOG" 2>&1; then
    tr '\0' '\n' < "$OUT_DIR/uki.cmdline" > "$OUT_DIR/uki.cmdline.txt"
    if grep -Fq 'lockdown=confidentiality' "$OUT_DIR/uki.cmdline.txt"; then
      pass "UKI cmdline contains lockdown=confidentiality"
    else
      fail "UKI cmdline lacks lockdown=confidentiality"
    fi
    if [[ -n "$VERITY_ROOT_HASH" ]] && grep -Fq "$VERITY_ROOT_HASH" "$OUT_DIR/uki.cmdline.txt"; then
      pass "UKI cmdline contains supplied dm-verity root hash"
    elif [[ -z "$VERITY_ROOT_HASH" ]]; then
      block "EXAMOS_RELEASE_VERITY_ROOT_HASH is not supplied"
    else
      fail "UKI cmdline does not contain supplied dm-verity root hash"
    fi
  else
    block "unable to extract UKI .cmdline with objcopy"
  fi
fi

if [[ -z "$ROOTFS" || ! -f "$ROOTFS" || -z "$VERITY_TREE" || ! -f "$VERITY_TREE" || -z "$VERITY_ROOT_HASH" ]]; then
  block "rootfs, verity tree, and root hash must all be supplied"
elif ! command -v veritysetup >/dev/null; then
  block "veritysetup is unavailable"
elif veritysetup verify "$ROOTFS" "$VERITY_TREE" "$VERITY_ROOT_HASH" >>"$LOG" 2>&1; then
  pass "clean rootfs verifies against dm-verity tree"
else
  fail "clean rootfs fails dm-verity verification"
fi

if [[ -z "$EVENT_LOG" || ! -r "$EVENT_LOG" ]]; then
  block "raw TCG event log is not supplied"
elif python3 "$(cd "$(dirname "$0")/../.." && pwd)/tools/examos-eventlog-replay.py" --event-log "$EVENT_LOG" --json "$OUT_DIR/eventlog-replay.json" >>"$LOG" 2>&1; then
  pass "raw TCG event log replayed by supported parser"
else
  fail "raw TCG event log cannot be replayed"
fi

{
  [[ -n "$UKI" && -f "$UKI" ]] && sha256sum "$UKI"
  [[ -n "$DB_CERT" && -f "$DB_CERT" ]] && sha256sum "$DB_CERT"
  [[ -n "$ROOTFS" && -f "$ROOTFS" ]] && sha256sum "$ROOTFS"
  [[ -n "$VERITY_TREE" && -f "$VERITY_TREE" ]] && sha256sum "$VERITY_TREE"
  [[ -n "$EVENT_LOG" && -f "$EVENT_LOG" ]] && sha256sum "$EVENT_LOG"
  sha256sum "$LOG"
} > "$OUT_DIR/MANIFEST.sha256"

export EXAMOS_BOOT_EVIDENCE_STATUS=$([[ ${#FAILED[@]} -gt 0 ]] && echo FAIL || ([[ ${#BLOCKED[@]} -gt 0 ]] && echo BLOCKED || echo PASS))
export EXAMOS_BOOT_EVIDENCE_PASSED="$(printf '%s\n' "${PASSED[@]}")"
export EXAMOS_BOOT_EVIDENCE_BLOCKED="$(printf '%s\n' "${BLOCKED[@]}")"
export EXAMOS_BOOT_EVIDENCE_FAILED="$(printf '%s\n' "${FAILED[@]}")"
python3 - "$REPORT" <<'PY'
import json, os, sys
def values(name): return [x for x in os.environ.get(name, '').splitlines() if x]
open(sys.argv[1], 'w', encoding='utf-8').write(json.dumps({
  'schema': 'examos-boot-chain-evidence-v1',
  'status': os.environ['EXAMOS_BOOT_EVIDENCE_STATUS'],
  'passed': values('EXAMOS_BOOT_EVIDENCE_PASSED'),
  'blocked': values('EXAMOS_BOOT_EVIDENCE_BLOCKED'),
  'failed': values('EXAMOS_BOOT_EVIDENCE_FAILED'),
  'manifest': 'MANIFEST.sha256',
}, indent=2) + '\n')
PY
cat "$REPORT"
[[ "$EXAMOS_BOOT_EVIDENCE_STATUS" == PASS ]] && exit 0
[[ "$EXAMOS_BOOT_EVIDENCE_STATUS" == BLOCKED ]] && exit 2
exit 1
