#!/usr/bin/env bash
set -euo pipefail
umask 077

RUN_DIR="${EXAMOS_VH_RUN_DIR:-}"
[[ -n "$RUN_DIR" && -d "$RUN_DIR" ]] || {
    echo "[VH-VERITY] BLOCKED: set EXAMOS_VH_RUN_DIR to an existing evidence run." >&2
    exit 2
}
for tool in veritysetup python3; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "[VH-VERITY] BLOCKED: required tool not installed: $tool" >&2
        exit 2
    }
done

EVIDENCE="$RUN_DIR/dm-verity"
mkdir -m 700 -- "$EVIDENCE"
DATA="$EVIDENCE/data.bin"
TREE="$EVIDENCE/hash-tree.bin"

python3 - "$DATA" <<'PY'
import hashlib
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
with path.open("xb") as stream:
    for index in range(1024):
        digest = hashlib.sha256(index.to_bytes(8, "big")).digest()
        stream.write(digest * 128)
PY

veritysetup format --hash=sha256 --data-block-size=4096 --hash-block-size=4096 \
    "$DATA" "$TREE" > "$EVIDENCE/verity-format.txt" 2>&1
ROOT_HASH="$(awk -F':' '/Root hash:/ {gsub(/[[:space:]]/, "", $2); print $2; exit}' "$EVIDENCE/verity-format.txt")"
SALT="$(awk -F':' '/Salt:/ {gsub(/[[:space:]]/, "", $2); print $2; exit}' "$EVIDENCE/verity-format.txt")"
[[ "$ROOT_HASH" =~ ^[0-9a-fA-F]{64}$ ]] || {
    echo "[VH-VERITY] FAIL: veritysetup did not return a SHA-256 root hash." >&2
    exit 1
}
[[ "$SALT" =~ ^[0-9a-fA-F]+$ ]] || {
    echo "[VH-VERITY] FAIL: veritysetup did not return a valid salt." >&2
    exit 1
}
veritysetup verify "$DATA" "$TREE" "$ROOT_HASH" > "$EVIDENCE/verify-original.txt" 2>&1

python3 - "$DATA" "$EVIDENCE/single-block-corruption.bin" \
    "$EVIDENCE/multiple-block-corruption.bin" "$TREE" \
    "$EVIDENCE/corrupt-hash-tree.bin" <<'PY'
import pathlib
import sys

source, single, multiple, tree, corrupt_tree = map(pathlib.Path, sys.argv[1:])
data = source.read_bytes()
one = bytearray(data)
one[128] ^= 0x01
single.write_bytes(one)
many = bytearray(data)
for offset in (4096 + 17, 7 * 4096 + 41, 63 * 4096 + 9):
    many[offset] ^= 0x80
multiple.write_bytes(many)
corrupt = bytearray(tree.read_bytes())
hash_tree_offset = 4096
if len(corrupt) <= hash_tree_offset:
    raise SystemExit("veritysetup generated no hash-tree block after its superblock")
corrupt[hash_tree_offset] ^= 0x01
corrupt_tree.write_bytes(corrupt)
PY

expect_rejected() {
    local label="$1"
    shift
    if "$@" > "$EVIDENCE/$label.log" 2>&1; then
        echo "[VH-VERITY] FAIL: verifier accepted $label." >&2
        return 1
    fi
    if ! grep -qiE 'verification failed|verification of root hash failed' \
        "$EVIDENCE/$label.log"; then
        echo "[VH-VERITY] FAIL: $label failed for a reason other than integrity rejection." >&2
        cat "$EVIDENCE/$label.log" >&2
        return 1
    fi
    printf '[VH-VERITY] PASS: verifier rejected %s.\n' "$label"
}

expect_rejected single-block-corruption \
    veritysetup verify "$EVIDENCE/single-block-corruption.bin" "$TREE" "$ROOT_HASH"
expect_rejected multiple-block-corruption \
    veritysetup verify "$EVIDENCE/multiple-block-corruption.bin" "$TREE" "$ROOT_HASH"
expect_rejected corrupt-hash-tree \
    veritysetup verify "$DATA" "$EVIDENCE/corrupt-hash-tree.bin" "$ROOT_HASH"
wrong_hash="${ROOT_HASH:1}"
[[ "${ROOT_HASH:0:1}" == "0" ]] && wrong_hash="1$wrong_hash" || wrong_hash="0$wrong_hash"
expect_rejected incorrect-root-hash \
    veritysetup verify "$DATA" "$TREE" "$wrong_hash"

python3 - "$EVIDENCE" "$ROOT_HASH" "$SALT" <<'PY'
import hashlib
import json
import pathlib
import sys
from datetime import datetime, timezone

directory = pathlib.Path(sys.argv[1])
def digest(name):
    h = hashlib.sha256()
    with (directory / name).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()

record = {
    "schema": "sppio.virtual-hardware.dm-verity.v1",
    "generated_at_utc": datetime.now(timezone.utc).isoformat(),
    "data_sha256": digest("data.bin"),
    "hash_tree_sha256": digest("hash-tree.bin"),
    "root_hash_sha256": sys.argv[2],
    "data_block_size": 4096,
    "hash_block_size": 4096,
    "salt": sys.argv[3],
    "checks": {
        "original_data": "PASS",
        "single_block_corruption_rejected": "PASS",
        "multiple_block_corruption_rejected": "PASS",
        "corrupt_hash_tree_rejected": "PASS",
        "incorrect_root_hash_rejected": "PASS",
        "read_only_device_mapper_mount": "BLOCKED: root/device-mapper mount not attempted",
        "boot_chain_integration": "BLOCKED: existing image dm-verity boot integration is not configured",
    },
    "test_scope": "disposable regular files; not the production root filesystem",
}
with (directory / "verity-results.json").open("x", encoding="utf-8") as stream:
    json.dump(record, stream, indent=2, sort_keys=True)
    stream.write("\n")
PY

printf '[VH-VERITY] PASS: dm-verity rejected altered data, hash tree, and root hash on disposable files.\n'
