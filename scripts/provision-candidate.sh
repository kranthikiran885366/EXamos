#!/usr/bin/env bash
# =============================================================================
# ExamOS Candidate Credential Provisioning Script
# Usage (single):  provision-candidate.sh CANDIDATE_ID [credential-store]
# Usage (batch):   provision-candidate.sh candidates.csv [credential-store]
#
# CSV format (batch): one entry per line — candidate_id,pin
#   - Lines beginning with '#' are treated as comments and skipped.
#   - Blank lines are skipped.
#   - The PIN column must be 6–128 characters.
#   - candidate_id must match [A-Za-z0-9._-]{1,63}
#
# The credential store file uses the format understood by
# candidate_credentials_validate() in server/login/candidate_login.c:
#   candidate_id:pbkdf2_iterations:salt_hex:derived_key_hex
# =============================================================================
set -euo pipefail

# ---------------------------------------------------------------------------
# Shared provisioning function — derives PBKDF2 key and appends to store.
# Arguments: $1=candidate_id  $2=pin  $3=store_path
# ---------------------------------------------------------------------------
provision_one() {
    local cid="$1" pin="$2" store_path="$3"

    if [[ ! "$cid" =~ ^[A-Za-z0-9._-]{1,63}$ ]]; then
        echo "ERROR: Invalid candidate_id '$cid' — must match [A-Za-z0-9._-]{1,63}" >&2
        return 1
    fi
    if [ "${#pin}" -lt 6 ] || [ "${#pin}" -gt 128 ]; then
        echo "ERROR: PIN for '$cid' is ${#pin} characters — must be 6–128 characters" >&2
        return 1
    fi

    local iterations=600000
    local salt
    salt=$(openssl rand -hex 32)
    local derived
    derived=$(openssl kdf -keylen 32 -kdfopt digest:SHA256 \
        -kdfopt "pass:${pin}" \
        -kdfopt "hexsalt:${salt}" \
        -kdfopt "iter:${iterations}" \
        PBKDF2 | tr -d ':\r\n' | tr 'A-F' 'a-f')

    umask 0077
    local temporary
    temporary=$(mktemp)

    if [ -f "$store_path" ]; then
        # Remove any existing entry for this candidate (idempotent re-provision)
        awk -F: -v id="$cid" '$1 != id' "$store_path" > "$temporary"
    fi
    printf '%s:%d:%s:%s\n' "$cid" "$iterations" "$salt" "$derived" >> "$temporary"
    install -o root -g exam -m 0640 "$temporary" "$store_path"
    rm -f -- "$temporary"
    echo "Provisioned $cid in $store_path"
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
arg_one="${1:-}"
store_path="${2:-/etc/examos/candidates.conf}"

if [ -z "$arg_one" ]; then
    echo "Usage: $0 CANDIDATE_ID [credential-store]" >&2
    echo "       $0 candidates.csv [credential-store]" >&2
    exit 2
fi

# ---------------------------------------------------------------------------
# Batch mode: argument is a .csv file
# ---------------------------------------------------------------------------
if [[ "$arg_one" == *.csv ]]; then
    if [ ! -f "$arg_one" ]; then
        echo "ERROR: CSV file '$arg_one' not found." >&2
        exit 2
    fi

    echo "=== Batch provisioning from $arg_one ==="
    success_count=0
    fail_count=0
    line_num=0

    while IFS=',' read -r raw_cid raw_pin rest; do
        (( line_num++ )) || true

        # Strip carriage returns (Windows CSV)
        raw_cid="${raw_cid//$'\r'/}"
        raw_pin="${raw_pin//$'\r'/}"

        # Skip comment lines and blank lines
        [[ "$raw_cid" =~ ^[[:space:]]*# ]] && continue
        [[ -z "${raw_cid// }" ]]           && continue

        # Trim leading/trailing whitespace
        cid="${raw_cid#"${raw_cid%%[![:space:]]*}"}"
        cid="${cid%"${cid##*[![:space:]]}"}"
        pin="${raw_pin#"${raw_pin%%[![:space:]]*}"}"
        pin="${pin%"${pin##*[![:space:]]}"}"

        if [ -z "$pin" ]; then
            echo "WARNING: Line $line_num — no PIN column for '$cid', skipping." >&2
            (( fail_count++ )) || true
            continue
        fi

        if provision_one "$cid" "$pin" "$store_path"; then
            (( success_count++ )) || true
        else
            (( fail_count++ )) || true
        fi
    done < "$arg_one"

    echo ""
    echo "=== Batch complete: $success_count provisioned, $fail_count failed ==="
    [ "$fail_count" -eq 0 ] || exit 1
    exit 0
fi

# ---------------------------------------------------------------------------
# Single-candidate interactive mode
# ---------------------------------------------------------------------------
candidate_id="$arg_one"

if [[ ! "$candidate_id" =~ ^[A-Za-z0-9._-]{1,63}$ ]]; then
    echo "Usage: $0 CANDIDATE_ID [credential-store]" >&2
    exit 2
fi

read -r -s -p "Candidate PIN (minimum 6 characters): " pin
echo
provision_one "$candidate_id" "$pin" "$store_path"
