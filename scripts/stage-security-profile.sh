#!/usr/bin/env bash
# Called by the existing production builder. Never modifies the build host.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAGE="${1:?usage: stage-security-profile.sh STAGE_DIRECTORY}"
if [[ "$STAGE" != /* || "$STAGE" == / || ! -d "$STAGE" ]]; then
    echo 'A separate absolute image staging directory is required' >&2
    exit 2
fi
install -d "$STAGE/etc/examos"
make -C "$ROOT/agent/runtime-guard" all
make -C "$ROOT/agent/runtime-lsm" all
install -D -m 0755 "$ROOT/agent/runtime-guard/examos-runtime-guard" "$STAGE/usr/local/bin/examos-runtime-guard"
install -D -m 0755 "$ROOT/agent/runtime-lsm/examos-bpf-lsm" "$STAGE/usr/local/bin/examos-bpf-lsm"
install -D -m 0644 "$ROOT/agent/runtime-lsm/runtime.bpf.o" "$STAGE/usr/lib/examos/runtime.bpf.o"
for tool in keylime_gate.py release_provenance.py revoke_runtime_secrets.py; do
    install -D -m 0644 "$ROOT/tools/$tool" "$STAGE/usr/local/libexec/examos/$tool"
done
install -D -m 0644 "$ROOT/image/security/ima-policy" "$STAGE/etc/ima/ima-policy"
for unit in examos-ima-policy.service examos-bpf-lsm.service examos-runtime-guard.service examos-secret-lifecycle.service; do
    install -D -m 0644 "$ROOT/image/security/$unit" "$STAGE/etc/systemd/system/$unit"
    mkdir -p "$STAGE/etc/systemd/system/multi-user.target.wants"
    ln -sfn "../$unit" "$STAGE/etc/systemd/system/multi-user.target.wants/$unit"
done
install -D -m 0644 "$ROOT/image/security/lockdown-revoke.conf" \
    "$STAGE/etc/systemd/system/examos-lockdown-failed.target.d/revoke.conf"
for service in examos-kiosk examos-preflight; do
    install -D -m 0644 "$ROOT/image/security/measured-kiosk.conf" \
        "$STAGE/etc/systemd/system/$service.service.d/measured.conf"
done
# Do not bake enrollment credentials or mTLS keys into a reusable OS image.
# Deployment provisions /etc/examos/keylime-gate.json and a real Keylime agent.
printf 'measured\n' > "$STAGE/etc/examos/security-profile"
echo 'Measured profile staged; enrollment and firmware qualification are required before boot.'
