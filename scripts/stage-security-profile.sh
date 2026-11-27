#!/usr/bin/env bash
# Stage SPPIO / ExamOS security profile artifacts without embedding deployment credentials.
set -euo pipefail

STAGE="${1:?usage: stage-security-profile.sh <stage_dir>}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

mkdir -p "$STAGE/usr/local/bin" \
         "$STAGE/usr/lib/examos/bpf" \
         "$STAGE/usr/local/libexec/examos" \
         "$STAGE/etc/ima" \
         "$STAGE/etc/examos" \
         "$STAGE/etc/systemd/system/multi-user.target.wants"

if [ -f "$ROOT/rust-services/target/release/sppio-securityd" ]; then
    install -m 0755 "$ROOT/rust-services/target/release/sppio-securityd" "$STAGE/usr/local/bin/sppio-securityd"
elif [ -f "$ROOT/rust-services/target/debug/sppio-securityd" ]; then
    install -m 0755 "$ROOT/rust-services/target/debug/sppio-securityd" "$STAGE/usr/local/bin/sppio-securityd"
else
    cargo build --release --manifest-path "$ROOT/rust-services/Cargo.toml"
    install -m 0755 "$ROOT/rust-services/target/release/sppio-securityd" "$STAGE/usr/local/bin/sppio-securityd"
fi

make -C "$ROOT/kernel/bpf_lsm" all >/dev/null
make -C "$ROOT/kernel/bpf_xdp" all >/dev/null
install -m 0644 "$ROOT/kernel/bpf_lsm/examos_lsm.bpf.o" "$STAGE/usr/lib/examos/bpf/examos_lsm.bpf.o"
install -m 0644 "$ROOT/kernel/bpf_xdp/examos_xdp_filter.bpf.o" "$STAGE/usr/lib/examos/bpf/examos_xdp_filter.bpf.o"

install -m 0644 "$ROOT/image/overlay/etc/ima/ima-policy" "$STAGE/etc/ima/ima-policy"
install -m 0755 "$ROOT/tools/keylime_gate.py" "$STAGE/usr/local/libexec/examos/keylime_gate.py"
install -m 0755 "$ROOT/tools/revoke_runtime_secrets.py" "$STAGE/usr/local/libexec/examos/revoke_runtime_secrets.py"

for unit in sppio-securityd.service examos-bpf-lsm.service examos-xdp-filter.service examos-pfr-verify.service examos-ab-commit.service; do
    install -m 0644 "$ROOT/image/overlay/etc/systemd/system/$unit" "$STAGE/etc/systemd/system/$unit"
    ln -sf "../$unit" "$STAGE/etc/systemd/system/multi-user.target.wants/$unit"
done

printf 'measured\n' > "$STAGE/etc/examos/security-profile"
rm -f "$STAGE/etc/examos/keylime-gate.json"
