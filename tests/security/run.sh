#!/usr/bin/env bash
# Software-only security stack regressions. No device writes or TPM mutation.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD=$(mktemp -d "${TMPDIR:-/tmp}/examos-security-tests.XXXXXX")
trap 'rm -rf -- "$BUILD"' EXIT
cd "$ROOT"
CC="${CC:-cc}"
PG_INCLUDEDIR="${PG_INCLUDEDIR:-$(pg_config --includedir)}"
read -r -a PG_LINK <<< "${PG_LIBS:--lpq}"
"$CC" -Wall -Wextra -Werror tests/server/ml-kem-test.c common/examos_kem.c -lcrypto -o "$BUILD/kem"
"$BUILD/kem"
make -C server test-release-signature
"$CC" -Wall -Wextra -Werror -g -fsanitize=address,undefined -I"$PG_INCLUDEDIR" \
    tests/server/key-release-lifetime-test.c server/gateway/key_release.c \
    -lcrypto "${PG_LINK[@]}" -Wl,--wrap=RAND_bytes -o "$BUILD/key-lifetime"
"$BUILD/key-lifetime"
make -C agent/runtime-guard BUILD_DIR="$BUILD/guard" test all
make -C agent/runtime-lsm BUILD_DIR="$BUILD/lsm" all
python3 -m unittest discover -s tests/security -v
bash -n scripts/stage-security-profile.sh scripts/build-full-image.sh image/scripts/03-p2-lockdown.sh
readelf -S "$BUILD/lsm/runtime.bpf.o" | grep -q '\.BTF'
echo 'PASS: software security-stack regressions (hardware enforcement not tested)'
