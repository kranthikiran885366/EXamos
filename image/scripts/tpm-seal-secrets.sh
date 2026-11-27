#!/usr/bin/env bash
# =============================================================================
# ExamOS H6 — TPM-Sealed Secret Management
#
# Seals all runtime secrets to TPM PCR state so they can only be unsealed
# on the specific appliance after a verified measured boot. An attacker with
# physical access to the disk cannot read secrets without the TPM.
#
# What is sealed:
#   EXAMOS_AGENT_API_TOKEN     → active generation under /etc/examos/sealed/generations/
#   EXAMOS_PROCTOR_API_TOKEN   → active generation under /etc/examos/sealed/generations/
#   EXAMOS_EVENT_SIGNING_KEY   → active generation under /etc/examos/sealed/generations/
#   EXAMOS_VARIANT_SECRET      → active generation under /etc/examos/sealed/generations/
#   EXAMOS_LEDGER_HMAC_KEY     → active generation under /etc/examos/sealed/generations/
#   EXAMOS_DATABASE_PASSWORD  → active generation under /etc/examos/sealed/generations/
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
#   EXAMOS_EXAM_KEY_KEK=<key> \
#   EXAMOS_DATABASE_PASSWORD_FILE=/run/examos/db_password \
#   bash /usr/local/sbin/tpm-seal-secrets.sh
#
# Unsealing (called at service startup by examos-unseal.service):
#   bash /usr/local/sbin/tpm-unseal-secrets.sh
#
# Requirements: tpm2-tools and tpm2-abrmd (tpm2_createprimary, tpm2_create, tpm2_load,
#   tpm2_unseal, tpm2_pcrread, tpm2_startauthsession, tpm2_policypcr,
#   tpm2_policycommandcode, tpm2_flushcontext)
# =============================================================================
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "[TPM-SEAL] FATAL: sealing must run as root on the target device." >&2
    exit 1
fi
SEAL_DIR="/etc/examos/sealed"
PCR_LIST="sha256:0,4,7,11"
umask 077
exec 9>/run/lock/examos-tpm-seal.lock
flock -n 9 || { echo "[TPM-SEAL] FATAL: another sealing operation is active." >&2; exit 1; }
WORK_DIR="$(mktemp -d /run/examos-tpm-seal.XXXXXX)" || exit 1
PRIMARY_CTX="$WORK_DIR/primary.ctx"
POLICY_CTX="$WORK_DIR/policy.ctx"
POLICY_DIGEST="$WORK_DIR/policy.digest"
PCR_VALUES="$WORK_DIR/pcr-values.bin"
ACTIVE_BUNDLE_TMP=""
GENERATION_STAGE=""
GENERATION_FINAL=""
CURRENT_LINK_TMP=""
cleanup() {
    tpm2_flushcontext "$POLICY_CTX" 2>/dev/null || true
    tpm2_flushcontext "$PRIMARY_CTX" 2>/dev/null || true
    if [ -d "$WORK_DIR" ]; then
        find "$WORK_DIR" -type f -exec shred -u -n 1 -z {} + 2>/dev/null || true
        rm -rf -- "$WORK_DIR"
    fi
    [ -z "$ACTIVE_BUNDLE_TMP" ] || shred -u -n 1 -z "$ACTIVE_BUNDLE_TMP" 2>/dev/null || rm -f -- "$ACTIVE_BUNDLE_TMP"
    [ -z "$CURRENT_LINK_TMP" ] || rm -f -- "$CURRENT_LINK_TMP"
    if [ -n "$GENERATION_STAGE" ] && [ -d "$GENERATION_STAGE" ]; then
        rm -rf -- "$GENERATION_STAGE"
    fi
    unset EXAMOS_AGENT_API_TOKEN EXAMOS_PROCTOR_API_TOKEN EXAMOS_EVENT_SIGNING_KEY
    unset EXAMOS_VARIANT_SECRET EXAMOS_LEDGER_HMAC_KEY
    unset EXAMOS_DATABASE_PASSWORD EXAMOS_DATABASE_PASSWORD_FILE
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

log()  { echo "[TPM-SEAL] $*"; }
fail() { echo "[TPM-SEAL] FATAL: $*" >&2; exit 1; }

if [ -x /usr/local/bin/pfr-800-193-verify.sh ]; then
    /usr/local/bin/pfr-800-193-verify.sh || fail "NIST SP 800-193 PFR verification failed; refusing to seal secrets on unverified boot."
fi

# -----------------------------------------------------------------------
# Prerequisites
# -----------------------------------------------------------------------
for tool in tpm2_createprimary tpm2_create tpm2_load tpm2_unseal \
            tpm2_pcrread tpm2_startauthsession tpm2_policypcr \
            tpm2_policycommandcode tpm2_flushcontext systemctl base64 sync flock; do
    command -v "$tool" >/dev/null 2>&1 || \
        fail "Required tool not found: $tool"
done

# Check that the OS exposes a TPM interface. A device node alone does not
# establish that the TPM is physical; production enrollment separately
# requires manufacturer certificate and organization approval.
if [ ! -c /dev/tpmrm0 ] && [ ! -c /dev/tpm0 ]; then
    fail "No TPM device found. A TPM 2.0 interface is required."
fi
systemctl start tpm2-abrmd.service || fail "TPM resource manager could not be started."
systemctl is-active --quiet tpm2-abrmd.service || fail "TPM resource manager is not active."
export TPM2TOOLS_TCTI=tabrmd

log "TPM interface available; this check does not identify physical versus virtual TPM hardware."

mkdir -p "$SEAL_DIR"
[ ! -L "$SEAL_DIR" ] || fail "Sealed-secret directory must not be a symbolic link."
chown root:root "$SEAL_DIR"
chmod 0700 "$SEAL_DIR"
GENERATIONS_DIR="$SEAL_DIR/generations"
mkdir -p "$GENERATIONS_DIR"
[ ! -L "$GENERATIONS_DIR" ] || fail "TPM generation directory must not be a symbolic link."
chown root:root "$GENERATIONS_DIR"
chmod 0700 "$GENERATIONS_DIR"
GENERATION_STAGE="$(mktemp -d "$GENERATIONS_DIR/.staging.XXXXXX")"
chmod 0700 "$GENERATION_STAGE"

# -----------------------------------------------------------------------
# Secrets to seal — read from environment
# -----------------------------------------------------------------------
declare -A SECRETS=(
    ["agent-api-token"]="${EXAMOS_AGENT_API_TOKEN:-}"
    ["proctor-api-token"]="${EXAMOS_PROCTOR_API_TOKEN:-}"
    ["event-signing-key"]="${EXAMOS_EVENT_SIGNING_KEY:-}"
    ["variant-secret"]="${EXAMOS_VARIANT_SECRET:-}"
    ["ledger-hmac-key"]="${EXAMOS_LEDGER_HMAC_KEY:-}"
    ["exam-key-kek"]="${EXAMOS_EXAM_KEY_KEK:-}"
)
unset DB_PASSWORD_FILE DB_PASSWORD_ENV val
DB_PASSWORD_ENV="${EXAMOS_DATABASE_PASSWORD:-}"
unset EXAMOS_AGENT_API_TOKEN EXAMOS_PROCTOR_API_TOKEN EXAMOS_EVENT_SIGNING_KEY
unset EXAMOS_VARIANT_SECRET EXAMOS_LEDGER_HMAC_KEY EXAMOS_DATABASE_PASSWORD
unset EXAMOS_EXAM_KEY_KEK
DB_PASSWORD_FILE="${EXAMOS_DATABASE_PASSWORD_FILE:-}"
unset EXAMOS_DATABASE_PASSWORD_FILE
if [ -n "$DB_PASSWORD_FILE" ]; then
    [ ! -L "$DB_PASSWORD_FILE" ] && [ -f "$DB_PASSWORD_FILE" ] || fail "Database password file must be a regular non-symlink file."
    DB_PASSWORD_OWNER="$(stat -c %u -- "$DB_PASSWORD_FILE")"
    DB_PASSWORD_MODE="$(stat -c %a -- "$DB_PASSWORD_FILE")"
    DB_PASSWORD_SIZE="$(stat -c %s -- "$DB_PASSWORD_FILE")"
    [ "$DB_PASSWORD_OWNER" = 0 ] && (( 8#$DB_PASSWORD_MODE & 0077 == 0 )) &&
        (( DB_PASSWORD_SIZE > 0 && DB_PASSWORD_SIZE <= 128 )) ||
        fail "Database password file must be root-owned, private, and at most 128 bytes."
    DB_READY_MARKER="/run/examos/postgres-ready"
    [ ! -L "$DB_READY_MARKER" ] && [ -f "$DB_READY_MARKER" ] || fail "PostgreSQL provisioning did not complete in this boot."
    DB_READY_OWNER="$(stat -c %u -- "$DB_READY_MARKER")"
    DB_READY_MODE="$(stat -c %a -- "$DB_READY_MARKER")"
    DB_READY_SIZE="$(stat -c %s -- "$DB_READY_MARKER")"
    [ "$DB_READY_OWNER" = 0 ] && (( 8#$DB_READY_MODE & 0077 == 0 )) &&
        (( DB_READY_SIZE > 0 && DB_READY_SIZE <= 256 )) || fail "PostgreSQL readiness marker is unsafe."
    SECRETS[database-password]="$(cat -- "$DB_PASSWORD_FILE")"
else
    SECRETS[database-password]="$DB_PASSWORD_ENV"
fi
unset DB_PASSWORD_ENV

for name in "${!SECRETS[@]}"; do
    val="${SECRETS[$name]}"
    if [ -z "$val" ] || [ "${#val}" -lt 32 ]; then
        fail "Secret '${name}' is not set or shorter than 32 characters. \
Set all required environment variables before running."
    fi
    if [[ ! "$val" =~ ^[A-Za-z0-9_-]+$ ]] || (( ${#val} > 128 )); then
        fail "Secret '${name}' must use base64url or hexadecimal encoding and fit the TPM 128-byte sealed-data limit."
    fi
done
log "All ${#SECRETS[@]} secrets validated (minimum entropy length and TPM size limit)."

# -----------------------------------------------------------------------
# Read current PCR values — seal to THIS boot's measurements
# -----------------------------------------------------------------------
log "Reading current PCR values for sealing policy..."
tpm2_pcrread "$PCR_LIST" --output "$PCR_VALUES"
PCR_SUMMARY=$(tpm2_pcrread "$PCR_LIST" 2>/dev/null | grep -E '^\s+[0-9]+:' || true)
log "Current PCR values:"
echo "$PCR_SUMMARY" | while read -r line; do log "  $line"; done

# -----------------------------------------------------------------------
# Create a PCR policy digest: the sealed object can only be unsealed
# when PCR 0,4,7,11 match their values at sealing time.
# -----------------------------------------------------------------------
log "Creating PCR policy digest..."
# tpm2-tools defaults to a trial session when no session type is selected.
tpm2_startauthsession -S "$POLICY_CTX"
tpm2_policypcr -S "$POLICY_CTX" -l "$PCR_LIST" \
    --pcr "$PCR_VALUES" -L "$POLICY_DIGEST"
tpm2_policycommandcode -S "$POLICY_CTX" -L "$POLICY_DIGEST" TPM2_CC_Unseal
# Save PolicyPCR output from the same trial session; do not hash an empty policy.
tpm2_flushcontext "$POLICY_CTX" 2>/dev/null || true
[ -s "$POLICY_DIGEST" ] || fail "TPM did not produce a PCR policy digest"
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
    SEALED_FILE="${GENERATION_STAGE}/${name}.sealed"
    PUB_FILE="$WORK_DIR/${name}.pub"
    PRIV_FILE="$WORK_DIR/${name}.priv"
    SECRET_FILE="$WORK_DIR/${name}.secret"

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
        -i "$SECRET_FILE" >/dev/null

    # The bundle contains only the TPM-protected public/private blobs.
    ACTIVE_BUNDLE_TMP="$(mktemp "$GENERATION_STAGE/.${name}.sealed.XXXXXX")"
    {
        printf 'EXMS\n'
        base64 --wrap=0 -- "$PUB_FILE"
        printf '\n'
        base64 --wrap=0 -- "$PRIV_FILE"
        printf '\n'
    } > "$ACTIVE_BUNDLE_TMP"
    chmod 0400 "$ACTIVE_BUNDLE_TMP"
    sync -f "$ACTIVE_BUNDLE_TMP"
    mv -f -- "$ACTIVE_BUNDLE_TMP" "$SEALED_FILE"
    ACTIVE_BUNDLE_TMP=""
    sync -f "$GENERATION_STAGE"

    rm -f -- "$SECRET_FILE" "$PUB_FILE" "$PRIV_FILE"

    log "  → Sealed. Bundle: $(stat -c %s "$SEALED_FILE") bytes"
done

# Publish a complete generation with one atomic symlink replacement. Unseal
# follows only this pointer, so power loss cannot expose a mixed secret set.
EXPECTED_SECRET_COUNT="${#SECRETS[@]}"
ACTUAL_SECRET_COUNT="$(find "$GENERATION_STAGE" -maxdepth 1 -type f -name '*.sealed' | wc -l)"
[ "$ACTUAL_SECRET_COUNT" -eq "$EXPECTED_SECRET_COUNT" ] || fail "Staged TPM generation is incomplete."
sync -f "$GENERATION_STAGE"
GENERATION_SUFFIX="${GENERATION_STAGE##*.}"
GENERATION_FINAL="$GENERATIONS_DIR/generation-$GENERATION_SUFFIX"
[ ! -e "$GENERATION_FINAL" ] || fail "Generated TPM generation identifier already exists."
mv -T -- "$GENERATION_STAGE" "$GENERATION_FINAL"
GENERATION_STAGE=""
sync -f "$GENERATIONS_DIR"
CURRENT_LINK_TMP="$SEAL_DIR/.current.$$.tmp"
ln -s "generations/generation-$GENERATION_SUFFIX" "$CURRENT_LINK_TMP"
mv -Tf -- "$CURRENT_LINK_TMP" "$SEAL_DIR/current"
CURRENT_LINK_TMP=""
sync -f "$SEAL_DIR"

# Remove legacy flat-layout bundles only after the new active generation is
# durable. They must not remain as an implicit downgrade/recovery source.
rm -f -- "$SEAL_DIR"/agent-api-token.sealed "$SEAL_DIR"/proctor-api-token.sealed \
    "$SEAL_DIR"/event-signing-key.sealed "$SEAL_DIR"/variant-secret.sealed \
    "$SEAL_DIR"/ledger-hmac-key.sealed "$SEAL_DIR"/database-password.sealed
sync -f "$SEAL_DIR"

# Once the active pointer is durable, remove obsolete generations. Retaining
# old TPM blobs after key rotation would preserve access to retired secrets.
while IFS= read -r -d '' old_generation; do
    [ "$old_generation" = "$GENERATION_FINAL" ] || rm -rf -- "$old_generation"
done < <(find "$GENERATIONS_DIR" -mindepth 1 -maxdepth 1 -type d -name 'generation-*' -print0)
sync -f "$GENERATIONS_DIR"

# Clean up PCR files and primary context
tpm2_flushcontext "$PRIMARY_CTX" 2>/dev/null || true
rm -f -- "$PCR_VALUES" "$POLICY_DIGEST" "$PRIMARY_CTX"
if [ -n "$DB_PASSWORD_FILE" ] && [ -f "$DB_PASSWORD_FILE" ]; then
    PASSWORD_FS="$(findmnt -n -o FSTYPE --target "$DB_PASSWORD_FILE" 2>/dev/null || true)"
    if [ "$PASSWORD_FS" = "tmpfs" ]; then
        rm -f -- "$DB_PASSWORD_FILE"
    fi
fi

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

if [ "$(id -u)" -ne 0 ]; then
    echo "[TPM-UNSEAL] FATAL: unsealing must run as root." >&2
    exit 1
fi
SEAL_DIR="/etc/examos/sealed"
ACTIVE_SEAL_DIR=""
RUNTIME_DIR="/run/examos/secrets"
PCR_LIST="sha256:0,4,7,11"
umask 077
exec 9>/run/lock/examos-tpm-unseal.lock
flock -n 9 || { echo "[TPM-UNSEAL] FATAL: another unseal operation is active." >&2; exit 1; }
WORK_DIR="$(mktemp -d /run/examos-tpm-unseal.XXXXXX)" || exit 1
PRIMARY_CTX="$WORK_DIR/primary.ctx"
PCR_VALUES="$WORK_DIR/pcr-values.bin"
UNSEAL_COMPLETE=0
cleanup() {
    tpm2_flushcontext "$PRIMARY_CTX" 2>/dev/null || true
    rm -rf -- "$WORK_DIR"
    if [ "$UNSEAL_COMPLETE" -ne 1 ]; then
        rm -f -- "$RUNTIME_DIR"/runtime.env "$RUNTIME_DIR"/runtime.env.tmp \
            "$RUNTIME_DIR"/proctor.env "$RUNTIME_DIR"/proctor.env.tmp \
            "$RUNTIME_DIR"/agent.env "$RUNTIME_DIR"/agent.env.tmp \
            "$RUNTIME_DIR"/database-url "$RUNTIME_DIR"/database-url.tmp \
            "$RUNTIME_DIR"/database-password \
            "$RUNTIME_DIR"/agent-api-token \
            "$RUNTIME_DIR"/proctor-api-token "$RUNTIME_DIR"/event-signing-key \
            "$RUNTIME_DIR"/variant-secret "$RUNTIME_DIR"/ledger-hmac-key
    fi
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

log()  { echo "[TPM-UNSEAL] $*"; }
fail() { echo "[TPM-UNSEAL] FATAL: $*" >&2; exit 1; }
for tool in tpm2_createprimary tpm2_load tpm2_unseal tpm2_pcrread \
            tpm2_startauthsession tpm2_policypcr tpm2_policycommandcode \
            tpm2_flushcontext systemctl base64 flock; do
    command -v "$tool" >/dev/null 2>&1 || fail "Required TPM tool is missing: ${tool}"
done
systemctl is-active --quiet tpm2-abrmd.service || fail "TPM access broker is not active."
export TPM2TOOLS_TCTI=tabrmd

install -d -m 0700 "$RUNTIME_DIR"
[ ! -L "$RUNTIME_DIR" ] || fail "Runtime-secret directory must not be a symbolic link."
chown root:root "$RUNTIME_DIR"
chmod 0700 "$RUNTIME_DIR"
[ ! -L "$SEAL_DIR" ] && [ -d "$SEAL_DIR" ] || fail "Sealed-secret directory is missing or unsafe."
SEAL_DIR_OWNER="$(stat -c %u -- "$SEAL_DIR")"
SEAL_DIR_MODE="$(stat -c %a -- "$SEAL_DIR")"
[ "$SEAL_DIR_OWNER" = 0 ] && (( 8#$SEAL_DIR_MODE & 0077 == 0 )) || fail "Sealed-secret directory must be root-owned and private."
if [ -e "$SEAL_DIR/current" ] || [ -L "$SEAL_DIR/current" ]; then
    [ -L "$SEAL_DIR/current" ] || fail "Active TPM generation pointer must be a symbolic link."
    ACTIVE_TARGET="$(readlink -- "$SEAL_DIR/current")"
    [[ "$ACTIVE_TARGET" =~ ^generations/generation-[A-Za-z0-9]{6}$ ]] || fail "Active TPM generation pointer is invalid."
    GENERATIONS_DIR="$SEAL_DIR/generations"
    [ ! -L "$GENERATIONS_DIR" ] && [ -d "$GENERATIONS_DIR" ] || fail "TPM generation directory is missing or unsafe."
    ACTIVE_SEAL_DIR="$SEAL_DIR/$ACTIVE_TARGET"
    [ ! -L "$ACTIVE_SEAL_DIR" ] && [ -d "$ACTIVE_SEAL_DIR" ] || fail "Active TPM generation is missing or unsafe."
    ACTIVE_OWNER="$(stat -c %u -- "$ACTIVE_SEAL_DIR")"
    ACTIVE_MODE="$(stat -c %a -- "$ACTIVE_SEAL_DIR")"
    [ "$ACTIVE_OWNER" = 0 ] && (( 8#$ACTIVE_MODE & 0077 == 0 )) || fail "Active TPM generation must be root-owned and private."
else
    # Read existing pre-generation installations only when every required
    # secret bundle is present; incomplete legacy state is never accepted.
    if [ -d "$SEAL_DIR/generations" ] && find "$SEAL_DIR/generations" -mindepth 1 -maxdepth 1 -type d -name 'generation-*' -print -quit | grep -q .; then
        fail "TPM generations exist but the active pointer is missing; refusing legacy fallback. Re-run sealing to publish a complete generation."
    fi
    ACTIVE_SEAL_DIR="$SEAL_DIR"
fi
rm -f -- "$RUNTIME_DIR"/runtime.env "$RUNTIME_DIR"/runtime.env.tmp \
    "$RUNTIME_DIR"/proctor.env "$RUNTIME_DIR"/proctor.env.tmp \
    "$RUNTIME_DIR"/agent.env "$RUNTIME_DIR"/agent.env.tmp \
    "$RUNTIME_DIR"/database-url "$RUNTIME_DIR"/database-password \
    "$RUNTIME_DIR"/agent-api-token \
    "$RUNTIME_DIR"/proctor-api-token "$RUNTIME_DIR"/event-signing-key \
    "$RUNTIME_DIR"/variant-secret "$RUNTIME_DIR"/ledger-hmac-key

# Verify TPM
[ -c /dev/tpmrm0 ] || [ -c /dev/tpm0 ] || fail "TPM character device not found"

# Read current PCRs (must match sealing-time policy)
tpm2_pcrread "$PCR_LIST" --output "$PCR_VALUES"

# Create primary
tpm2_createprimary -C o -g sha256 -G rsa -c "$PRIMARY_CTX" >/dev/null

FAILED=0
SEALED_FILE_COUNT="$(find "$ACTIVE_SEAL_DIR" -maxdepth 1 -type f -name '*.sealed' | wc -l)"
[ "$SEALED_FILE_COUNT" -eq 6 ] || fail "Active TPM generation must contain exactly six sealed bundles."
for sealed_file in "$ACTIVE_SEAL_DIR"/*.sealed; do
    [ -f "$sealed_file" ] || continue
    name=$(basename "$sealed_file" .sealed)
    case "$name" in
        agent-api-token|proctor-api-token|event-signing-key|variant-secret|ledger-hmac-key|database-password) ;;
        *) fail "Unexpected TPM-sealed secret name: ${name}" ;;
    esac
    pub_file="$WORK_DIR/${name}.pub"
    priv_file="$WORK_DIR/${name}.priv"
    obj_ctx="$WORK_DIR/${name}.ctx"
    out_file="${RUNTIME_DIR}/${name}"
    policy_session="$WORK_DIR/${name}-policy.ctx"

    # Read exactly the version marker and two base64 payloads; reject trailing data.
    BUNDLE_OWNER="$(stat -c %u -- "$sealed_file")"
    BUNDLE_MODE="$(stat -c %a -- "$sealed_file")"
    BUNDLE_SIZE="$(stat -c %s -- "$sealed_file")"
    [ "$BUNDLE_OWNER" = 0 ] && (( 8#$BUNDLE_MODE & 0077 == 0 )) &&
        (( BUNDLE_SIZE >= 16 && BUNDLE_SIZE <= 1048576 )) || fail "Sealed bundle ownership, permissions, or size is invalid."
    exec 3< "$sealed_file"
    IFS= read -r bundle_magic <&3 || fail "Sealed bundle header is missing."
    IFS= read -r pub_encoded <&3 || fail "Sealed bundle public blob is missing."
    IFS= read -r priv_encoded <&3 || fail "Sealed bundle private blob is missing."
    if IFS= read -r bundle_extra <&3; then fail "Sealed bundle has trailing data."; fi
    exec 3<&-
    [ "$bundle_magic" = "EXMS" ] && [ -n "$pub_encoded" ] && [ -n "$priv_encoded" ] ||
        fail "Sealed bundle format is invalid."
    printf '%s\n' "$pub_encoded" | base64 --decode > "$pub_file" || fail "Sealed public blob encoding is invalid."
    printf '%s\n' "$priv_encoded" | base64 --decode > "$priv_file" || fail "Sealed private blob encoding is invalid."
    unset pub_encoded priv_encoded bundle_magic bundle_extra

    # Load object
    tpm2_load -C "$PRIMARY_CTX" -u "$pub_file" -r "$priv_file" \
        -c "$obj_ctx" >/dev/null

    # Start policy session and satisfy PCR policy
    tpm2_startauthsession --policy-session -S "$policy_session"
    tpm2_policypcr -S "$policy_session" -l "$PCR_LIST" --pcr "$PCR_VALUES"
    tpm2_policycommandcode -S "$policy_session" TPM2_CC_Unseal

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

for required_name in agent-api-token proctor-api-token event-signing-key variant-secret ledger-hmac-key database-password; do
    [ -f "$ACTIVE_SEAL_DIR/$required_name.sealed" ] || fail "Required TPM-sealed bundle is missing: $required_name"
done

tpm2_flushcontext "$PRIMARY_CTX" 2>/dev/null || true
rm -f -- "$PRIMARY_CTX" "$PCR_VALUES"

if [ "$FAILED" -gt 0 ]; then
    fail "${FAILED} secret(s) could not be unsealed — appliance boot is blocked."
fi
declare -A ENV_NAMES=(
    [agent-api-token]=EXAMOS_AGENT_API_TOKEN
    [proctor-api-token]=EXAMOS_PROCTOR_API_TOKEN
    [event-signing-key]=EXAMOS_EVENT_SIGNING_KEY
    [variant-secret]=EXAMOS_VARIANT_SECRET
    [ledger-hmac-key]=EXAMOS_LEDGER_HMAC_KEY
    [exam-key-kek]=EXAMOS_EXAM_KEY_KEK
    [database-password]=EXAMOS_DATABASE_PASSWORD
)
DB_CONFIG_FILE="/etc/examos/db-connection.conf"
[ ! -L "$DB_CONFIG_FILE" ] && [ -f "$DB_CONFIG_FILE" ] || fail "PostgreSQL connection config is missing or not a regular file."
DB_CONFIG_OWNER="$(stat -c %u -- "$DB_CONFIG_FILE")"
DB_CONFIG_MODE="$(stat -c %a -- "$DB_CONFIG_FILE")"
DB_CONFIG_SIZE="$(stat -c %s -- "$DB_CONFIG_FILE")"
[ "$DB_CONFIG_OWNER" = 0 ] && (( 8#$DB_CONFIG_MODE & 0022 == 0 )) &&
    (( DB_CONFIG_SIZE > 0 && DB_CONFIG_SIZE <= 4096 )) || fail "PostgreSQL connection config ownership, permissions, or size is invalid."
mapfile -t DB_CONFIG_LINES < "$DB_CONFIG_FILE"
[ "${#DB_CONFIG_LINES[@]}" -eq 1 ] || fail "PostgreSQL connection config must contain exactly one line."
DB_CONFIG="${DB_CONFIG_LINES[0]}"
[[ "$DB_CONFIG" == host=* && "$DB_CONFIG" != *'"'* && "$DB_CONFIG" != *"'"* ]] ||
    fail "PostgreSQL connection config must use unquoted libpq keyword/value parameters."
DB_HOST_COUNT=0
DB_SSL_MODE_COUNT=0
DB_SSL_ROOT_COUNT=0
DB_SSL_ROOT_CERT=""
set -f
for db_option in $DB_CONFIG; do
    case "$db_option" in
        host=*)
            DB_HOST_COUNT=$((DB_HOST_COUNT + 1))
            [[ "$db_option" != host=/* ]] || fail "PostgreSQL connection config must use TCP, not a Unix socket."
            ;;
        sslmode=*)
            DB_SSL_MODE_COUNT=$((DB_SSL_MODE_COUNT + 1))
            [ "$db_option" = "sslmode=verify-full" ] || fail "PostgreSQL TLS must use sslmode=verify-full."
            ;;
        sslrootcert=*)
            DB_SSL_ROOT_COUNT=$((DB_SSL_ROOT_COUNT + 1))
            DB_SSL_ROOT_CERT="${db_option#sslrootcert=}"
            ;;
        password=*) fail "PostgreSQL connection config must not contain a plaintext password." ;;
    esac
done
set +f
[ "$DB_HOST_COUNT" -eq 1 ] && [ "$DB_SSL_MODE_COUNT" -eq 1 ] &&
    [ "$DB_SSL_ROOT_COUNT" -eq 1 ] && [ -n "$DB_SSL_ROOT_CERT" ] &&
    [ -f "$DB_SSL_ROOT_CERT" ] && [ ! -L "$DB_SSL_ROOT_CERT" ] ||
    fail "PostgreSQL connection config must have one host, verify-full TLS, and one existing CA certificate."
ENV_TMP="${RUNTIME_DIR}/runtime.env.tmp"
PROCTOR_ENV_TMP="${RUNTIME_DIR}/proctor.env.tmp"
AGENT_ENV_TMP="${RUNTIME_DIR}/agent.env.tmp"
: > "$ENV_TMP"
: > "$PROCTOR_ENV_TMP"
: > "$AGENT_ENV_TMP"
chmod 0600 "$ENV_TMP"
chmod 0600 "$PROCTOR_ENV_TMP"
chmod 0600 "$AGENT_ENV_TMP"
unset value
for name in "${!ENV_NAMES[@]}"; do
    value_file="${RUNTIME_DIR}/${name}"
    [ -s "$value_file" ] || fail "required secret ${name} was not unsealed"
    value=$(cat "$value_file")
    [[ "$value" != *$'\n'* && "$value" != *$'\r'* ]] || fail "secret ${name} contains a newline"
    [ "${#value}" -ge 32 ] || fail "secret ${name} is shorter than 32 characters"
    if [ "$name" = "database-password" ]; then
        [[ "$value" =~ ^[A-Za-z0-9_-]+$ ]] && [ "${#value}" -le 128 ] || fail "Database password has invalid encoding or size."
        DATABASE_URL_TMP="${RUNTIME_DIR}/database-url.tmp"
        install -m 0600 /dev/null "$DATABASE_URL_TMP"
        printf '%s password=%s\n' "$DB_CONFIG" "$value" > "$DATABASE_URL_TMP"
        mv -f -- "$DATABASE_URL_TMP" "${RUNTIME_DIR}/database-url"
        rm -f -- "$value_file"
    elif [ "$name" = "proctor-api-token" ]; then
        printf 'EXAMOS_PROCTOR_API_TOKEN=%s\n' "$value" >> "$PROCTOR_ENV_TMP"
        rm -f -- "$value_file"
    elif [ "$name" = "agent-api-token" ]; then
        printf 'EXAMOS_AGENT_API_TOKEN=%s\n' "$value" >> "$AGENT_ENV_TMP"
        rm -f -- "$value_file"
    else
        printf '%s=%s\n' "${ENV_NAMES[$name]}" "$value" >> "$ENV_TMP"
        rm -f -- "$value_file"
    fi
done
printf 'EXAMOS_DATABASE_URL_FILE=%s/database-url\n' "$RUNTIME_DIR" >> "$ENV_TMP"
mv -f "$ENV_TMP" "${RUNTIME_DIR}/runtime.env"
mv -f "$PROCTOR_ENV_TMP" "${RUNTIME_DIR}/proctor.env"
mv -f "$AGENT_ENV_TMP" "${RUNTIME_DIR}/agent.env"
chmod 0400 "${RUNTIME_DIR}/runtime.env"
chmod 0400 "${RUNTIME_DIR}/agent.env"
chown root:exam "${RUNTIME_DIR}/proctor.env"
chmod 0440 "${RUNTIME_DIR}/proctor.env"
log "All secrets unsealed to ${RUNTIME_DIR}"
chown root:exam "$RUNTIME_DIR"
chmod 0710 "$RUNTIME_DIR"
UNSEAL_COMPLETE=1
UNSEAL

log "Unseal script written: /usr/local/sbin/tpm-unseal-secrets.sh"

echo ""
log "TPM sealing complete. Secrets sealed to PCR policy $PCR_LIST"
log "Install examos-unseal.service to run tpm-unseal-secrets.sh at each boot."
log "Published sealed generation: $GENERATION_FINAL"
log ""
log "IMPORTANT: Delete the environment variables containing plaintext secrets"
log "after sealing. They should not persist in shell history or process env."
