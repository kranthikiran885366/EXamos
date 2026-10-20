#!/usr/bin/env bash
# =============================================================================
# ExamOS Phase 3 — Development Trust Key Generator
# image/trust/generate-dev-keys.sh
#
# Generates self-signed RSA-2048 test Secure Boot key material for use in:
#   - QEMU/OVMF development VMs
#   - CI pipelines (throwaway keys destroyed after the run)
#   - Local developer testing
#
# TEST ONLY — NOT FOR PRODUCTION.
#
# Production keys must be:
#   - Generated offline on an air-gapped HSM
#   - Never committed to Git
#   - Handled under a documented key ceremony procedure
#
# Usage:
#   bash image/trust/generate-dev-keys.sh [--force]
#
# Output files (all 600 permissions):
#   PK.key, PK.crt, KEK.key, KEK.crt, db.key, db.crt, pcr-policy.key
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FORCE=0
for arg in "$@"; do
    [ "$arg" = "--force" ] && FORCE=1
done

echo "[TrustKeys] Generating ExamOS P3 development Secure Boot keys..."
echo "[TrustKeys] Output directory: $SCRIPT_DIR"
echo "[TrustKeys] TEST ONLY — NOT FOR PRODUCTION"
echo ""

# Check prerequisites
if ! command -v openssl >/dev/null 2>&1; then
    echo "[TrustKeys] ERROR: openssl is required but not installed." >&2
    exit 1
fi

KEY_BITS=2048
DAYS=3650
SUBJ_PREFIX="/C=XX/ST=Dev/L=Dev/O=ExamOS-Dev/OU=TestOnly"

generate_key_cert() {
    local name="$1"
    local cn="$2"
    local key_file="${SCRIPT_DIR}/${name}.key"
    local crt_file="${SCRIPT_DIR}/${name}.crt"

    if [ -f "$key_file" ] && [ "$FORCE" -eq 0 ]; then
        echo "[TrustKeys]   Skipping $name (already exists; use --force to regenerate)"
        return 0
    fi

    echo "[TrustKeys]   Generating $name ($cn)..."

    openssl req -newkey "rsa:${KEY_BITS}" \
        -nodes \
        -keyout "$key_file" \
        -x509 \
        -days "$DAYS" \
        -out "$crt_file" \
        -subj "${SUBJ_PREFIX}/CN=${cn}" \
        2>/dev/null

    chmod 600 "$key_file"
    chmod 644 "$crt_file"

    echo "[TrustKeys]   ✓ $key_file (RSA-${KEY_BITS}, ${DAYS}d)"
    echo "[TrustKeys]   ✓ $crt_file"
}

generate_private_key() {
    local name="$1"
    local key_file="${SCRIPT_DIR}/${name}.key"

    if [ -f "$key_file" ] && [ "$FORCE" -eq 0 ]; then
        echo "[TrustKeys]   Skipping $name (already exists; use --force to regenerate)"
        return 0
    fi

    echo "[TrustKeys]   Generating $name (private key only)..."
    openssl genrsa -out "$key_file" "$KEY_BITS" 2>/dev/null
    chmod 600 "$key_file"
    echo "[TrustKeys]   ✓ $key_file (RSA-${KEY_BITS})"
}

# Generate the Secure Boot key hierarchy
generate_key_cert "PK"  "ExamOS-Dev-PK-TEST-ONLY"
generate_key_cert "KEK" "ExamOS-Dev-KEK-TEST-ONLY"
generate_key_cert "db"  "ExamOS-Dev-DB-TEST-ONLY"

# PCR policy signing key (private key only — self-contained)
generate_private_key "pcr-policy"

echo ""
echo "[TrustKeys] Development key generation complete."
echo "[TrustKeys]"
echo "[TrustKeys] Files created:"
ls -la "$SCRIPT_DIR"/*.key "$SCRIPT_DIR"/*.crt 2>/dev/null | \
    awk '{print "[TrustKeys]   " $0}'
echo ""
echo "[TrustKeys] ⚠  REMINDER: These are TEST ONLY keys."
echo "[TrustKeys]    Do NOT enroll these into production UEFI firmware."
echo "[TrustKeys]    Do NOT commit private key files (.key) to Git."
echo ""

# Verify keys exist (gate check for CI)
MISSING=0
for f in PK.key PK.crt KEK.key KEK.crt db.key db.crt pcr-policy.key; do
    if [ ! -f "${SCRIPT_DIR}/${f}" ]; then
        echo "[TrustKeys] MISSING: $f" >&2
        MISSING=1
    fi
done

if [ "$MISSING" -eq 1 ]; then
    echo "[TrustKeys] ERROR: One or more key files are missing." >&2
    exit 1
fi

echo "[TrustKeys] All 7 trust assets present — P3 trust key gate: PASS"
exit 0
