#!/usr/bin/env bash
set -euo pipefail

WORKSPACE="$(cd "$(dirname "$0")/.." && pwd)"

if (( $# < 1 || $# > 2 )); then
    echo "Usage: $0 CANDIDATE_ID [runtime-credential-store]" >&2
    echo "This provisions only a runtime store; credentials are never written to the image overlay." >&2
    exit 2
fi

store_path="${2:-/etc/examos/candidates.conf}"
exec sudo -- "$WORKSPACE/scripts/provision-candidate.sh" "$1" "$store_path"
