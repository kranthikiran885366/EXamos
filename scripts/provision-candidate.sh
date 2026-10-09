#!/usr/bin/env bash
set -euo pipefail

candidate_id="${1:-}"
store_path="${2:-/etc/examos/candidates.conf}"
if [[ ! "$candidate_id" =~ ^[A-Za-z0-9._-]{1,63}$ ]]; then
    echo "Usage: $0 CANDIDATE_ID [credential-store]" >&2
    exit 2
fi
read -r -s -p "Candidate PIN (minimum 6 characters): " pin
echo
if [ "${#pin}" -lt 6 ] || [ "${#pin}" -gt 128 ]; then
    echo "PIN length must be between 6 and 128 characters" >&2
    exit 2
fi

iterations=600000
salt=$(openssl rand -hex 32)
derived=$(openssl kdf -keylen 32 -kdfopt digest:SHA256 -kdfopt "pass:$pin" \
    -kdfopt "hexsalt:$salt" -kdfopt "iter:$iterations" PBKDF2 | tr -d ':\r\n' | tr 'A-F' 'a-f')
unset pin
umask 0077
temporary=$(mktemp)
if [ -f "$store_path" ]; then
    awk -F: -v id="$candidate_id" '$1 != id' "$store_path" >"$temporary"
fi
printf '%s:%d:%s:%s\n' "$candidate_id" "$iterations" "$salt" "$derived" >>"$temporary"
install -o root -g exam -m 0640 "$temporary" "$store_path"
rm -f -- "$temporary"
echo "Provisioned $candidate_id in $store_path"
