#!/usr/bin/env bash
# Retired legacy suite: it generated synthetic quote signatures and must not be
# used as attestation or release evidence.
set -euo pipefail

printf '%s\n' '[P3-SUITE] BLOCKED: synthetic attestation fixtures are retired.' >&2
printf '%s\n' '[P3-SUITE] Run production-registry.sh and swtpm-quote-smoke.sh for software checks.' >&2
printf '%s\n' '[P3-SUITE] Physical TPM, production trust, server-issued challenges, and key release remain separate qualification gates.' >&2
exit 2