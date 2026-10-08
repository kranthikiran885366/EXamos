#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT_DIR="$ROOT/artifacts/p0"
mkdir -p "$ARTIFACT_DIR"

printf '%s\n' "========================================"
printf '%s\n' "          EXAMOS P0 STATUS             "
printf '%s\n' "========================================"

if ! bash "$ROOT/tests/p0/host-check.sh"; then
  printf '%s\n' "P0 RESULT: FAIL"
  printf '%s\n' "Reason: host prerequisites are not satisfied in this environment."
  printf '%s\n' "========================================"
  cat > "$ARTIFACT_DIR/results.json" <<'EOF'
{
  "phase": "P0",
  "status": "FAIL",
  "checks": {
    "host": false,
    "architecture": false,
    "kvm": false,
    "qemu": false,
    "ovmf": false,
    "swtpm": false,
    "mkosi": false,
    "repository": false,
    "build": false,
    "boot": false,
    "ci": false
  },
  "gate": "BLOCKED",
  "reason": "The current environment is not a supported Linux build host; /dev/kvm, UEFI, and required build tools are absent."
}
EOF
  exit 1
fi

bash "$ROOT/tests/p0/examos-doctor.sh"
bash "$ROOT/tests/p0/repository-check.sh"

cat > "$ARTIFACT_DIR/results.json" <<'EOF'
{
  "phase": "P0",
  "status": "NOT_RUN",
  "checks": {
    "host": true,
    "architecture": true,
    "kvm": true,
    "qemu": false,
    "ovmf": false,
    "swtpm": false,
    "mkosi": false,
    "repository": true,
    "build": false,
    "boot": false,
    "ci": false
  },
  "gate": "NOT_RUN",
  "reason": "Host checks passed in a supported Linux environment must be verified before later P0 steps run."
}
EOF

printf '%s\n' "P0 RESULT: NOT_RUN"
printf '%s\n' "========================================"
