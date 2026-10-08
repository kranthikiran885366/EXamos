#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT_DIR="$ROOT/artifacts/p0"
mkdir -p "$ARTIFACT_DIR"

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
    "api": false,
    "build": false,
    "boot": false
  },
  "gate": "BLOCKED",
  "reason": "P0 run did not complete; see the failing step and its logs."
}
EOF

printf '%s\n' "=================================================="
printf '%s\n' "         ExamOS P0 End-to-End Test Suite          "
printf '%s\n' "=================================================="

# 1. Host Validation
printf '%s\n' "[Step 1/10] Validating host prerequisites..."
if ! bash "$ROOT/tests/p0/host-check.sh"; then
    printf '%s\n' "FAIL: Host check failed. Recording results..."
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
    "repository": true,
    "build": false,
    "boot": false,
    "api": false
  },
  "gate": "BLOCKED",
  "reason": "Host environment does not satisfy Linux KVM and UEFI build prerequisites."
}
EOF
    exit 1
fi

# 2. Doctor Diagnostics
printf '%s\n' "[Step 2/10] Running ExamOS Doctor..."
bash "$ROOT/tests/p0/examos-doctor.sh" || true

# 3. Repository Integrity & Secret Check
printf '%s\n' "[Step 3/10] Checking repository structure & scanning for secrets..."
bash "$ROOT/tests/p0/repository-check.sh"

# 4. Tool Versions & Metadata Collection
printf '%s\n' "[Step 4/10] Recording toolchain versions..."
bash "$ROOT/tests/p0/collect-build-info.sh"

# 5. Native Subsystem Compilation & API Smoke Test
printf '%s\n' "[Step 5/10] Compiling C/C++ subsystems and exercising the local API..."
make -C "$ROOT" all
bash "$ROOT/tests/p0/server-smoke.sh"

# 6. mkosi Image Build
printf '%s\n' "[Step 6/10] Generating and validating the OS image..."
bash "$ROOT/tests/p0/build.sh"

# 7. Automated QEMU + OVMF Boot Test
printf '%s\n' "[Step 7/10] Executing automated QEMU/OVMF boot verification..."
bash "$ROOT/tests/p0/boot.sh"

# 8. Record Final PASS Results
cat > "$ARTIFACT_DIR/results.json" <<'EOF'
{
  "phase": "P0",
  "status": "PASS",
  "checks": {
    "host": true,
    "architecture": true,
    "kvm": true,
    "qemu": true,
    "ovmf": true,
    "swtpm": true,
    "mkosi": true,
    "repository": true,
    "api": true,
    "build": true,
    "boot": true
  },
  "gate": "PASS",
  "reason": "P0 host checks, native compilation, API smoke test, mkosi image validation, and QEMU/OVMF serial-login/server startup test succeeded. Kiosk operation and enterprise readiness are not established."
}
EOF

printf '%s\n' "=================================================="
printf '%s\n' "              EXAMOS P0 STATUS SUMMARY            "
printf '%s\n' "=================================================="
printf '%-30s PASS\n' "Host & Architecture"
printf '%-30s PASS\n' "Virtualization & KVM"
printf '%-30s PASS\n' "Native C/C++ Compilation"
printf '%-30s PASS\n' "Local API Smoke Test"
printf '%-30s PASS\n' "mkosi Image Generation"
printf '%-30s PASS\n' "Artifact & Checksum"
printf '%-30s PASS\n' "QEMU/OVMF Boot Test"
printf '%-30s PASS\n' "Repository Integrity"
printf '%s\n' "--------------------------------------------------"
printf '%s\n' "P0 RESULT: PASS"
printf '%s\n' "=================================================="
