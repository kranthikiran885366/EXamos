#!/usr/bin/env bash
# Prove journal replay clears EXT4_FEATURE_INCOMPAT_RECOVER on an image file.
set -euo pipefail
WORKSPACE="$(cd "$(dirname "$0")/../.." && pwd)"
# shellcheck source=../../scripts/examos-lib.sh
source "$WORKSPACE/scripts/examos-lib.sh"

TMP="$(mktemp -d /tmp/examos-ext4-ro.XXXXXX)"
trap 'rm -rf "$TMP"' EXIT
IMAGE="$TMP/root.ext4"

truncate -s 64M "$IMAGE"
mkfs.ext4 -F -L root-x86-64 "$IMAGE" >/dev/null

python3 - "$IMAGE" << 'PY'
import struct, sys
path = sys.argv[1]
RECOVER = 0x4
with open(path, "r+b") as f:
    f.seek(1024)
    sb = bytearray(f.read(1024))
    incompat = struct.unpack_from("<I", sb, 0x60)[0]
    struct.pack_into("<I", sb, 0x60, incompat | RECOVER)
    f.seek(1024)
    f.write(sb)
PY

features="$(tune2fs -l "$IMAGE" | awk -F': *' '/Filesystem features:/ { print $2 }')"
case " $features " in
    *" needs_recovery "*) ;;
    *) echo "FAIL: could not plant needs_recovery for the regression" >&2; exit 1 ;;
esac

examos_ext4_replay_journal_for_readonly "$IMAGE"

features="$(tune2fs -l "$IMAGE" | awk -F': *' '/Filesystem features:/ { print $2 }')"
case " $features " in
    *" needs_recovery "*)
        echo "FAIL: needs_recovery remains after replay" >&2
        exit 1
        ;;
esac
echo "PASS: ext4 journal replay clears needs_recovery"
