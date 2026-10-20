#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
git add -- \
  .gitignore \
  .github/workflows/p0.yml \
  image/p0/mkosi.conf \
  image/p0/sources.lock \
  image/p0/toolchain.lock \
  schemas/production-blocker-status.schema.json \
  scripts/p0.sh \
  scripts/production-readiness.sh \
  tests/p0/pin-check.sh \
  tests/p0/reproducible-build.sh \
  tests/p0/vmware-optical-boot.sh \
  tests/production/clean-source-gate.sh \
  tests/production/hardware-qualification-gate.sh \
  tests/production/trust-provisioning-gate.sh \
  tests/production/server-verified-tpm-challenge.sh \
  tests/production/external-acceptance-gate.sh \
  docs/production/README.md \
  docs/production/hardware-qualification.md \
  docs/production/signing-ceremony.md \
  docs/production/independent-assessment.md \
  docs/development/p0-production-completion.md \
  docs/security/BLOCKER_CLOSURE_REPORT.md \
  docs/security/PHYSICAL_DEVICE_TEST_PLAN.md \
  artifacts/production/.gitkeep
git diff --cached --stat
git commit -m "$(cat <<'EOF'
Record P0 production-readiness gates without claiming missing evidence.

Pin Debian snapshot sources and fail closed on VMware, hardware, trust, TPM, and independent review until those inputs exist.
EOF
)"
git log -1 --oneline
git status -sb | head -n 8
