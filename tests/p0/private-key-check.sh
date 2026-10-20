#!/usr/bin/env bash
set -euo pipefail

WORKSPACE="${1:-$(cd "$(dirname "$0")/../.." && pwd)}"
TRUST_DIR="$WORKSPACE/image/trust"
FINDINGS=()
HAS_IGNORED_DEV_KEYS=false

while IFS= read -r key_file; do
    relative_path="${key_file#"$WORKSPACE"/}"
    if [[ "$key_file" == "$TRUST_DIR/"* ]]; then
        case "${key_file##*/}" in
            PK.key|KEK.key|db.key|pcr-policy.key)
                if git -C "$WORKSPACE" ls-files --error-unmatch -- "$relative_path" >/dev/null 2>&1 ||
                    ! git -C "$WORKSPACE" check-ignore -q -- "$relative_path"; then
                    FINDINGS+=("$key_file (development key must remain untracked and ignored)")
                else
                    HAS_IGNORED_DEV_KEYS=true
                fi
                ;;
            *)
                FINDINGS+=("$key_file")
                ;;
        esac
    else
        FINDINGS+=("$key_file")
    fi
done < <(find "$WORKSPACE" -type d -name .git -prune -o -type f \
    \( -name '*.pem' -o -name '*.key' -o -name '*.pfx' -o -name '*.p12' \
       -o -name id_rsa -o -name id_ed25519 \) -print 2>/dev/null)

if [ "$HAS_IGNORED_DEV_KEYS" = true ]; then
    echo "[KEY-CHECK] WARNING: Local P3 test keys are present but untracked and Git-ignored; they are not production keys."
fi

if [ "${#FINDINGS[@]}" -gt 0 ]; then
    printf '[KEY-CHECK] FAIL: Unexpected or tracked key-like files:\n'
    printf '  %s\n' "${FINDINGS[@]}"
    exit 1
fi

echo "[KEY-CHECK] PASS: no tracked or unexpected key-like files."
