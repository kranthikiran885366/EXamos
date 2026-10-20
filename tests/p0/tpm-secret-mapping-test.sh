#!/usr/bin/env bash
# Static contract regression for TPM secret sealing/unsealing.
# Safe to run on a developer host: this test never talks to a TPM or writes keys.
set -euo pipefail

WORKSPACE="$(cd "$(dirname "$0")/../.." && pwd)"
SEAL_SCRIPT="$WORKSPACE/image/scripts/tpm-seal-secrets.sh"
SESSION_STORE="$WORKSPACE/server/login/session_store.c"
VMWARE_BUILDER="$WORKSPACE/scripts/build-vmware-image.sh"

grep -Fq '["ledger-hmac-key"]="${EXAMOS_LEDGER_HMAC_KEY:-}"' "$SEAL_SCRIPT"
grep -Fq '[ledger-hmac-key]=EXAMOS_LEDGER_HMAC_KEY' "$SEAL_SCRIPT"
grep -Fq 'getenv("EXAMOS_LEDGER_HMAC_KEY")' "$SESSION_STORE"

if grep -Eq 'session-hmac-key|EXAMOS_SESSION_HMAC_KEY' "$SEAL_SCRIPT"; then
    echo "FAIL: TPM secret map contains an unused duplicate session HMAC secret" >&2
    exit 1
fi

if grep -Eq 'vmware-dev-(agent|proctor)-token|ADMIN_PASSWORD_PLAINTEXT_DEV_ONLY=|EXAMOS_EVENT_SIGNING_KEY=0{32,}|EXAMOS_VARIANT_SECRET=0{32,}|EXAMOS_DEVICE_ID=vmware-dev-device|EXAM_URL=http://localhost|SALT="examos\.vm"|openssl passwd .*"examos"|root / examos|exam / exam' "$VMWARE_BUILDER"; then
    echo "FAIL: VMware image builder embeds fixed credentials or deployment values" >&2
    exit 1
fi

if grep -Eq 'EXAMOS_TPM_MODE=development|ExecStart=/bin/true' "$VMWARE_BUILDER"; then
    echo "FAIL: VMware image builder bypasses production provisioning controls" >&2
    exit 1
fi

if grep -Eq 'losetup -D|/root/examos-mkosi|/mnt/d/SEB BRO|rm -rf "\$VMDK"|rm -rf "\$MKOSI_WS"' "$VMWARE_BUILDER"; then
    echo "FAIL: VMware builder has global cleanup or a fixed destructive workspace/output path" >&2
    exit 1
fi

grep -Fq 'VMWARE_OUTPUT_DIR="${EXAMOS_VMWARE_OUTPUT_DIR:-$OUTPUT_PARENT/vmware-$RUN_ID}"' "$VMWARE_BUILDER"
grep -Fq 'EXAMOS_BUILD_RUN_ID must be a filename-safe identifier.' "$VMWARE_BUILDER"
grep -Fq 'trap cleanup EXIT' "$VMWARE_BUILDER"

echo "PASS: TPM secret mapping is consistent; VMware image uses unprovisioned inputs and isolated per-run outputs"
