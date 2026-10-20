#!/usr/bin/env bash
# =============================================================================
# ExamOS H6 — TPM-Sealed Secret Management
#
# Seals all runtime secrets to TPM PCR state so they can only be unsealed
# on the specific appliance after a verified measured boot. An attacker with
# physical access to the disk cannot read secrets without the TPM.
#
# What is sealed:
#   EXAMOS_AGENT_API_TOKEN     → /etc/examos/sealed/agent-api-token.sealed
#   EXAMOS_PROCTOR_API_TOKEN   → /etc/examos/sealed/proctor-api-token.sealed
#   EXAMOS_EVENT_SIGNING_KEY   → /etc/examos/sealed/event-signing-key.sealed
#   EXAMOS_VARIANT_SECRET      → /etc/examos/sealed/variant-secret.sealed
#   EXAMOS_LEDGER_HMAC_KEY     → /etc/examos/sealed/ledger-hmac-key.sealed
# The event ledger and session journal intentionally share
# EXAMOS_LEDGER_HMAC_KEY in the current server implementation.
#
# PCR policy: sealed to PCR 0,4,7,11 (same as attestation).
#   PCR 0  = CRTM / BIOS firmware
#   PCR 4  = Boot manager / UKI
#   PCR 7  = Secure Boot policy state
#   PCR 11 = dm-verity root hash
#
# When to run:
#   At DEPLOYMENT TIME after the appliance has completed a clean measured boot
#   with the production image. Run once per device; re-run after any firmware
#   or image update.
#
# NEVER run in a build script or CI — sealing requires the target TPM.
#
# Usage (on the target appliance as root):
#   EXAMOS_AGENT_API_TOKEN=<token> \
#   EXAMOS_PROCTOR_API_TOKEN=<token> \
#   EXAMOS_EVENT_SIGNING_KEY=<key> \
#   EXAMOS_VARIANT_SECRET=<secret> \
#   EXAMOS_LEDGER_HMAC_KEY=<key> \
#   bash /usr/local/sbin/tpm-seal-secrets.sh
#
# Unsealing (called at service startup by examos-unseal.service):
#   bash /usr/local/sbin/tpm-unseal-secrets.sh
#
# Requirements: tpm2-tools (tpm2_createprimary, tpm2_create, tpm2_load,
#   tpm2_unseal, tpm2_pcrread, tpm2_startauthsession, tpm2_policypcr,
#   tpm2_policycommandcode, tpm2_flushcontext)
# =============================================================================
set -euo pipefail

SEAL_DIR="/etc/examos/sealed"
PCR_LIST="sha256:0,4,7,11"
PRIMARY_CTX="/tmp/examos-seal-primary.ctx"
POLICY_CTX="/tmp/examos-seal-policy.ctx"
POLICY_DIGEST="/tmp/examos-seal-policy.digest"

log()  { echo "[TPM-SEAL] $*"; }
fail() { echo "[TPM-SEAL] FATAL: $*" >&2; exit 1; }

# -----------------------------------------------------------------------
# Prerequisites
# -----------------------------------------------------------------------
for tool in tpm2_createprimary tpm2_create tpm2_load tpm2_unseal \
            tpm2_pcrread tpm2_startauthsession tpm2_policypcr \
            tpm2_flushcontext tpm2_readpublic openssl; do
    command -v "$tool" >/dev/null 2>&1 || \
        fail "Required tool not found: $tool"
done

# Check TPM device is present
if [ ! -e /dev/tpmrm0 ] && [ ! -e /dev/tpm0 ]; then
    fail "No TPM device found. This script requires a physical TPM 2.0."
fi

log "TPM device: $(ls /dev/tpmrm0 /dev/tpm0 2>/dev/null | head -1)"

mkdir -p "$SEAL_DIR"
chmod 0700 "$SEAL_DIR"

# -----------------------------------------------------------------------
# Secrets to seal — read from environment
# -----------------------------------------------------------------------
declare -A SECRETS=(
    ["agent-api-token"]="${EXAMOS_AGENT_API_TOKEN:-}"
    ["proctor-api-token"]="${EXAMOS_PROCTOR_API_TOKEN:-}"
    ["event-signing-key"]="${EXAMOS_EVENT_SIGNING_KEY:-}"
    ["variant-secret"]="${EXAMOS_VARIANT_SECRET:-}"
    ["ledger-hmac-key"]="${EXAMOS_LEDGER_HMAC_KEY:-}"
)

for name in "${!SECRETS[@]}"; do
    val="${SECRETS[$name]}"
    if [ -z "$val" ] || [ "${#val}" -lt 32 ]; then
        fail "Secret '${name}' is not set or shorter than 32 characters. \
Set all required environment variables before running."
    fi
done
log "All ${#SECRETS[@]} secrets validated (≥32 chars each)."

# -----------------------------------------------------------------------
# Read current PCR values — seal to THIS boot's measurements
# -----------------------------------------------------------------------
log "Reading current PCR values for sealing policy..."
tpm2_pcrread "$PCR_LIST" --output /tmp/examos-pcr-values.bin
PCR_SUMMARY=$(tpm2_pcrread "$PCR_LIST" 2>/dev/null | grep -E '^\s+[0-9]+:' || true)
log "Current PCR values:"
echo "$PCR_SUMMARY" | while read -r line; do log "  $line"; done

# -----------------------------------------------------------------------
# Create a PCR policy digest: the sealed object can only be unsealed
# when PCR 0,4,7,11 match their values at sealing time.
# -----------------------------------------------------------------------
log "Creating PCR policy digest..."
tpm2_startauthsession -S "$POLICY_CTX" --policy-session 2>/dev/null || \
tpm2_startauthsession -S "$POLICY_CTX"
tpm2_policypcr -S "$POLICY_CTX" -l "$PCR_LIST" --pcr /tmp/examos-pcr-values.bin
tpm2_startauthsession -S "$POLICY_CTX" --policy-session -g sha256 \
    -L "$POLICY_DIGEST" 2>/dev/null || true
# Flush the trial session — we only need the digest
tpm2_flushcontext "$POLICY_CTX" 2>/dev/null || true
# If the session-based policy capture failed, use policypcr directly
if [ ! -f "$POLICY_DIGEST" ]; then
    tpm2_policypcr -l "$PCR_LIST" \
        --pcr /tmp/examos-pcr-values.bin \
        --policy "$POLICY_DIGEST" 2>/dev/null || \
    tpm2_policypcr -l "$PCR_LIST" \
        -L "$POLICY_DIGEST"
fi
log "Policy digest created: $POLICY_DIGEST"

# -----------------------------------------------------------------------
# Create primary key in Owner hierarchy
# -----------------------------------------------------------------------
log "Creating primary sealing key in TPM Owner hierarchy..."
tpm2_createprimary -C o -g sha256 -G rsa \
    -c "$PRIMARY_CTX" >/dev/null

# -----------------------------------------------------------------------
# Seal each secret
# -----------------------------------------------------------------------
for name in "${!SECRETS[@]}"; do
    SEALED_FILE="${SEAL_DIR}/${name}.sealed"
    PUB_FILE="/tmp/examos-seal-${name}.pub"
    PRIV_FILE="/tmp/examos-seal-${name}.priv"
    SECRET_FILE="/tmp/examos-seal-${name}.secret"

    log "Sealing: ${name} → ${SEALED_FILE}"

    # Write secret to temp file (mode 0600)
    install -m 0600 /dev/null "$SECRET_FILE"
    printf '%s' "${SECRETS[$name]}" > "$SECRET_FILE"

    # Create sealed object bound to the PCR policy
    tpm2_create \
        -C "$PRIMARY_CTX" \
        -u "$PUB_FILE" \
        -r "$PRIV_FILE" \
        -L "$POLICY_DIGEST" \
        -a "fixedtpm|fixedparent|noda|adminwithpolicy" \
        -i "$SECRET_FILE" \
        -G keyedhash >/dev/null

    # Pack public + private into a single sealed bundle
    python3 - "$PUB_FILE" "$PRIV_FILE" "$SEALED_FILE" <<'PYEOF'
import sys, struct
pub_path, priv_path, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
pub_data  = open(pub_path,  'rb').read()
priv_data = open(priv_path, 'rb').read()
# Format: magic(4) + pub_len(4, LE) + pub_data + priv_len(4, LE) + priv_data
magic = b'EXMS'
with open(out_path, 'wb') as f:
    f.write(magic)
    f.write(struct.pack('<I', len(pub_data)))
    f.write(pub_data)
    f.write(struct.pack('<I', len(priv_data)))
    f.write(priv_data)
print(f"[TPM-SEAL] Sealed bundle written: {out_path} ({len(pub_data)+len(priv_data)+12} bytes)")
PYEOF

    chmod 0400 "$SEALED_FILE"

    # Secure-delete temp files
    for tmpf in "$SECRET_FILE" "$PUB_FILE" "$PRIV_FILE"; do
        [ -f "$tmpf" ] && { dd if=/dev/urandom of="$tmpf" bs=1 \
            count="$(stat -c %s "$tmpf")" 2>/dev/null || true; rm -f "$tmpf"; }
    done

    log "  → Sealed. Bundle: $(stat -c %s "$SEALED_FILE") bytes"
done

# Clean up PCR files and primary context
tpm2_flushcontext "$PRIMARY_CTX" 2>/dev/null || true
rm -f /tmp/examos-pcr-values.bin "$POLICY_DIGEST" "$PRIMARY_CTX"

# -----------------------------------------------------------------------
# Install unseal script
# -----------------------------------------------------------------------
install -m 0700 /dev/null /usr/local/sbin/tpm-unseal-secrets.sh
cat > /usr/local/sbin/tpm-unseal-secrets.sh <<'UNSEAL'
#!/usr/bin/env bash
# ExamOS TPM Unseal — called by examos-unseal.service at boot
# Unseals secrets from TPM and writes them to /run/examos/secrets/
# (tmpfs — lost on reboot, which forces re-unseal every boot).
set -euo pipefail

SEAL_DIR="/etc/examos/sealed"
RUNTIME_DIR="/run/examos/secrets"
PRIMARY_CTX="/tmp/examos-unseal-primary-$$.ctx"
PCR_LIST="sha256:0,4,7,11"

log()  { echo "[TPM-UNSEAL] $*"; }
fail() { echo "[TPM-UNSEAL] FATAL: $*" >&2; exit 1; }

install -d -m 0700 "$RUNTIME_DIR"

# Verify TPM
[ -e /dev/tpmrm0 ] || [ -e /dev/tpm0 ] || fail "TPM device not found"

# Read current PCRs (must match sealing-time policy)
tpm2_pcrread "$PCR_LIST" --output /tmp/examos-unseal-pcrs-$$.bin

# Create primary
tpm2_createprimary -C o -g sha256 -G rsa -c "$PRIMARY_CTX" >/dev/null

FAILED=0
for sealed_file in "$SEAL_DIR"/*.sealed; do
    [ -f "$sealed_file" ] || continue
    name=$(basename "$sealed_file" .sealed)
    pub_file="/tmp/examos-unseal-${name}-$$.pub"
    priv_file="/tmp/examos-unseal-${name}-$$.priv"
    obj_ctx="/tmp/examos-unseal-${name}-$$.ctx"
    out_file="${RUNTIME_DIR}/${name}"
    policy_session="/tmp/examos-unseal-policy-$$.ctx"

    # Unpack bundle
    python3 - "$sealed_file" "$pub_file" "$priv_file" <<'PYEOF'
import sys, struct
bundle_path, pub_path, priv_path = sys.argv[1], sys.argv[2], sys.argv[3]
data = open(bundle_path, 'rb').read()
assert data[:4] == b'EXMS', "Invalid sealed bundle magic"
pub_len  = struct.unpack_from('<I', data, 4)[0]
pub_data = data[8:8+pub_len]
priv_off = 8 + pub_len
priv_len = struct.unpack_from('<I', data, priv_off)[0]
priv_data = data[priv_off+4:priv_off+4+priv_len]
open(pub_path,  'wb').write(pub_data)
open(priv_path, 'wb').write(priv_data)
PYEOF

    # Load object
    tpm2_load -C "$PRIMARY_CTX" -u "$pub_file" -r "$priv_file" \
        -c "$obj_ctx" >/dev/null

    # Start policy session and satisfy PCR policy
    tpm2_startauthsession --policy-session -S "$policy_session"
    tpm2_policypcr -S "$policy_session" -l "$PCR_LIST" \
        --pcr /tmp/examos-unseal-pcrs-$$.bin

    # Unseal
    install -m 0600 /dev/null "$out_file"
    if ! tpm2_unseal -c "$obj_ctx" -p "session:${policy_session}" \
        -o "$out_file" 2>/dev/null; then
        log "FAIL: Could not unseal ${name} — PCR mismatch or TPM error"
        rm -f "$out_file"
        FAILED=$((FAILED+1))
    else
        log "OK: ${name} unsealed to ${out_file}"
    fi

    tpm2_flushcontext "$policy_session" 2>/dev/null || true
    tpm2_flushcontext "$obj_ctx"        2>/dev/null || true
    rm -f "$pub_file" "$priv_file" "$obj_ctx"
done

tpm2_flushcontext "$PRIMARY_CTX" 2>/dev/null || true
rm -f "$PRIMARY_CTX" /tmp/examos-unseal-pcrs-$$.bin

if [ "$FAILED" -gt 0 ]; then
    fail "${FAILED} secret(s) could not be unsealed — appliance boot is blocked."
fi
declare -A ENV_NAMES=(
    [agent-api-token]=EXAMOS_AGENT_API_TOKEN
    [proctor-api-token]=EXAMOS_PROCTOR_API_TOKEN
    [event-signing-key]=EXAMOS_EVENT_SIGNING_KEY
    [variant-secret]=EXAMOS_VARIANT_SECRET
    [ledger-hmac-key]=EXAMOS_LEDGER_HMAC_KEY
)
ENV_TMP="${RUNTIME_DIR}/runtime.env.tmp"
: > "$ENV_TMP"
chmod 0600 "$ENV_TMP"
for name in "${!ENV_NAMES[@]}"; do
    value_file="${RUNTIME_DIR}/${name}"
    [ -s "$value_file" ] || fail "required secret ${name} was not unsealed"
    value=$(cat "$value_file")
    [[ "$value" != *$'\n'* && "$value" != *$'\r'* ]] || fail "secret ${name} contains a newline"
    [ "${#value}" -ge 32 ] || fail "secret ${name} is shorter than 32 characters"
    printf '%s=%s\n' "${ENV_NAMES[$name]}" "$value" >> "$ENV_TMP"
done
mv -f "$ENV_TMP" "${RUNTIME_DIR}/runtime.env"
chmod 0400 "${RUNTIME_DIR}/runtime.env"
log "All secrets unsealed to ${RUNTIME_DIR}"
chmod 0500 "$RUNTIME_DIR"
UNSEAL

log "Unseal script written: /usr/local/sbin/tpm-unseal-secrets.sh"

echo ""
log "TPM sealing complete. Secrets sealed to PCR policy $PCR_LIST"
log "Install examos-unseal.service to run tpm-unseal-secrets.sh at each boot."
log "Sealed bundles: $(ls -1 "$SEAL_DIR"/*.sealed 2>/dev/null | wc -l) file(s)"
log ""
log "IMPORTANT: Delete the environment variables containing plaintext secrets"
log "after sealing. They should not persist in shell history or process env."
