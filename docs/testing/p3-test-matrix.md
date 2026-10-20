# ExamOS P3 Test Matrix

## Overview

This document defines expected outcomes; it is not a report of a current run.
Historical files under `artifacts/p3/` are not current release proof. Only a
completed invocation of `tests/p3/gate.sh`, tied to its recorded start time,
source commit, and clean/dirty worktree state, is current development-gate
evidence. A dirty worktree means the recorded commit alone does not identify all
executed code. An interrupted run leaves the gate marked `IN_PROGRESS`.

The integration suite generates a run-local software TPM with `swtpm`, extends
PCR 7 with a deterministic test measurement so a zero-PCR disabled-Secure-Boot
case is distinguishable, reads its PCRs, creates an RSA Attestation Key by default (set
`EXAMOS_P3_TPM_AK_TYPE=ecc` to exercise ECDSA), obtains TPM-generated quotes
for fresh nonces, and independently checks TPM output with
`tpm2_checkquote`.
This dynamically exercises quote parsing, PCR selection, nonce binding, AK
signature verification, replay rejection, re-attestation, and device
revocation. It is software-TPM evidence only, not physical-TPM, EK trust,
measured-boot, or production-enrollment evidence.

Test suite: `tests/p3/attestation-suite.sh`
Gate script: `tests/p3/gate.sh`

## Environment Setup

```bash
# Source P3 config (sets all required env vars)
source image/config/p3.conf

# Generate dev trust keys if missing
bash image/trust/generate-dev-keys.sh

# Build server
make -C server all

# Keep generated evidence outside the source tree so it does not dirty a
# release checkout. Use durable storage for WSL/VM runs (not transient /tmp).
export EXAMOS_P3_ARTIFACT_DIR=/var/lib/examos/release-evidence/p3

# Run the development P3 gate
bash tests/p3/gate.sh
```

## Test Cases

| ID | Name | Expected Outcome | Failure Code |
|----|------|----------|-------------|
| P3-001 | Clean registered device — full attestation + key release | PASS | — |
| P3-002 | Modified UKI (wrong PCR 0) | FAIL | `P3_PCR_MISMATCH` |
| P3-003 | Secure Boot disabled (wrong PCR 7 = zeros) | FAIL | `P3_PCR_MISMATCH` |
| P3-004 | Replay attack (same evidence submitted twice) | FAIL | `P3_NONCE_REPLAY` |
| P3-005 | Unregistered EK fingerprint (software TPM / rogue machine) | FAIL | `P3_UNKNOWN_DEVICE` |
| P3-006 | Machine A evidence submitted for Machine B session | FAIL | `P3_SESSION_BINDING_FAIL` |
| P3-007 | Revoked release | FAIL | `P3_REVOKED_RELEASE` or `P3_UNKNOWN_RELEASE` |
| P3-008 | Forged quote signature (modified signature byte) | FAIL | `P3_INVALID_SIGNATURE` |
| P3-009 | Stale/wrong nonce (never issued by server) | FAIL | `P3_INVALID_NONCE` |
| P3-010 | PCR mismatch (wrong PCR 11) | FAIL | `P3_PCR_MISMATCH` |
| P3-011 | Unknown device ID (not in registry) | FAIL | `P3_UNKNOWN_DEVICE` |
| P3-012 | Unknown release ID (not in registry) | FAIL | `P3_UNKNOWN_RELEASE` |
| P3-013 | Key release on fabricated/unverified session | FAIL | `P3_SESSION_INVALID` |
| P3-014 | Missing event log hash | FAIL | `P3_EVENTLOG_INVALID` |
| P3-015 | Valid periodic re-attestation cycle | PASS | — |
| P3-016 | Revoked device | FAIL | `P3_REVOKED_DEVICE` |
| P3-017 | Expired challenge nonce | FAIL | `P3_NONCE_EXPIRED` |
| P3-018 | Device and release revocation invalidate active sessions, released keys, and re-attestation | PASS | — |

## Software TPM Fixture (Not Production Hardware Evidence)

The test fixture signs real TPM-generated `TPMS_ATTEST` bytes with an AK held
by a temporary software TPM. It seeds PCR 7 with a deterministic synthetic
measurement to exercise rejection of a zeroed PCR 7. PCR release values and
test registries are created under a temporary directory and discarded after
the run. They are not measured release trust data, do not establish AK-to-EK
credential activation, and must not certify production hardware.

Production challenge nonces expire after 120 seconds. Development tests may set
`EXAMOS_ATTESTATION_NONCE_TTL_SECONDS` to a value from 1 to 3600 seconds; the
suite uses 10 seconds and waits past that deadline in P3-017. The production
mode rejects any override other than 120 seconds.

## Production Registry Verification

Production mode requires separate detached SHA-256 signatures for the release
and device registries. Each registry must identify itself as `production`, use
its supported schema, and be signed by a configured RSA-3072+ or EC-256+
verification key. Release entries must use `APPROVED_PRODUCTION` and contain
non-placeholder UKI and SHA-256 PCR measurements. Device entries must contain a
valid EK fingerprint, explicit allowed release, and a recognized enrollment
state. Suspended, revoked, and retired devices are not registered for
attestation.

The relevant paths are configured with `EXAMOS_RELEASES_CONFIG`,
`EXAMOS_RELEASES_SIGNATURE`, `EXAMOS_RELEASES_PUBLIC_KEY`,
`EXAMOS_DEVICES_CONFIG`, `EXAMOS_DEVICES_SIGNATURE`, and
`EXAMOS_DEVICES_PUBLIC_KEY`. Default production paths are under
`/etc/examos/`. `tests/p3/production-registry.sh` generates disposable test
keys and exercises signed-manifest acceptance, tamper rejection, development
approval rejection, placeholder-hash rejection, and rejection of committed
development registries. These test keys and measurements are synthetic and
must never be deployed.

## Gate Criteria

P3 gate PASSES when all of these current checks pass:

1. All 7 development trust-key assets exist in `image/trust/`
2. All 18 software-TPM test cases produce their expected outcomes
3. Signed production registry acceptance and fail-closed checks pass with
   disposable test keys
4. The legacy Go verifier prototype compiles; it is explicitly build-only and
   cannot authorize attestations.

A P3 gate PASS is development validation only. It is not production release
certification and does not mean a production registry, signing key, device
enrollment, physical TPM, EK manufacturer chain, Secure Boot, event-log replay,
or measured release has been provisioned or verified.

## Physical TPM Path

The physical device path is intentionally separate from the swtpm suite.
`scripts/enroll-physical-tpm.sh --confirm-persist` requires Linux access to a
physical TPM device node, refuses occupied persistent handles, and emits an
enrollment request marked `PENDING_EXTERNAL_APPROVAL`. It does not clear the
TPM or authorize its own output. Enrollment remains incomplete until the EK
certificate chain is approved, MakeCredential/ActivateCredential succeeds,
and an external signer approves the registry binding.

`tests/p3/hardware-tpm-preflight.sh` is a physical-only local quote check. It
forces the device TCTI, reads the enrolled EK/AK handles, obtains PCRs, requests
a TPM quote over a fresh local nonce, and verifies it with `tpm2_checkquote`.
It writes protected hardware evidence but is not server-side attestation: the
nonce is not server-issued, and the script cannot certify the release, event
log, or production policy. If no `/dev/tpmrm0` or `/dev/tpm0` exists, it exits
`BLOCKED`; it never substitutes `swtpm`.

## Production Release Gate

`tests/p3/release-gate.py` is a separate production release evaluator. The
development gate above can never substitute for it. It returns:

- `PASS` only when the source worktree is clean, fresh 18/18 P3 evidence is
  bound to the current commit, and a detached-signature-verified production
  evidence manifest is complete, unexpired, and bound to that same commit.
- `FAIL` for failed checks, dirty source, malformed or inconsistent evidence,
  weak signing keys, signature failures, or incorrect source binding.
- `BLOCKED` when required evidence or production manifest inputs are absent.

CI also runs `python3 tests/p3/release-gate.py --credential-audit` to check that
the source image has only unprovisioned admin/proctor placeholders, no candidate
records or enrolled device identities, no baked agent secret file, and a
production-only server/agent unit configuration. This audit does not certify a
deployed image or provision runtime credentials.

Run it from the repository with production artifacts supplied outside the
source tree:

```bash
export EXAMOS_P3_ARTIFACT_DIR=/var/lib/examos/release-evidence/p3
export EXAMOS_RELEASE_EVIDENCE_MANIFEST=/var/lib/examos/release-evidence/manifest.json
export EXAMOS_RELEASE_EVIDENCE_SIGNATURE=/var/lib/examos/release-evidence/manifest.sig
export EXAMOS_RELEASE_EVIDENCE_PUBLIC_KEY=/etc/examos/trust/release-evidence.pub
export EXAMOS_RELEASE_GATE_REPORT=/var/lib/examos/release-evidence/gate.json
python3 tests/p3/release-gate.py
```

The manifest must be signed as the exact JSON file bytes using OpenSSL
`dgst -sha256 -sign` and must provide `_schema` equal to
`examos-release-evidence-v1`, `environment` equal to `production`,
`approval_status` equal to `APPROVED_PRODUCTION`, `source_tree_state` equal to
`CLEAN`, the exact `source_commit`, an active `revocation_status`, a future
timezone-qualified `expires_at`, and a non-empty `production_release_id`.
It must also include nonzero 64-hex-character SHA-256 values for
`image_sha256`, `uki_sha256`, `rootfs_sha256`, `verity_root_hash`, and
`sbom_sha256`, plus `p3_gate_results_sha256` and
`p3_suite_results_sha256` matching the exact external P3 JSON evidence files.
Its `evidence` object must mark each of these as `PASS`:
`reproducible_build`, `physical_tpm_quote`, `ek_chain_validation`,
`credential_activation`, `event_log_replay`, `secure_boot`,
`dm_verity_corruption_rejection`, `runtime_lockdown`,
`key_release_binding`, and `independent_approval`.

The configured public key must be RSA-3072+ or NIST P-256/P-384/P-521. The
organization must provision and protect that key out-of-band and must not
trust a test key or key stored in the source repository. This gate checks
signed assertions and their binding; it cannot independently perform or
authenticate the physical-hardware procedures those assertions describe.
Consequently production certification remains blocked until those procedures
are genuinely executed, independently approved, and their evidence is signed
by the organization's trusted release authority. The generated
`golden-pcr.json` is explicitly `NOT_PROVISIONED`; the collector no longer
emits fabricated PCR measurements.

## Interpreting Results

```
[SUITE] P3-001 (clean_registered_device): PASS
[SUITE] P3-002 (modified_uki): PASS         ← "PASS" means expected=FAIL actual=FAIL
[SUITE] P3-004 (replay_attack): PASS        ← replay correctly rejected
```

A test "PASSES" when the actual outcome matches the expected outcome. For security-negative tests (P3-002 through P3-014 and P3-016 through P3-018), PASS means the attack or expired challenge was correctly rejected, or revocation was enforced.

## Running Individual Tests

```bash
# Source config
source image/config/p3.conf

# Start server manually for debugging
EXAMOS_SERVER_PORT=9099 \
EXAMOS_LEDGER_PATH=/tmp/test-ledger.log \
EXAMOS_DEVICES_CONFIG=server/config/devices.json \
EXAMOS_RELEASES_CONFIG=server/config/releases.json \
EXAMOS_AGENT_API_TOKEN="$EXAMOS_AGENT_API_TOKEN" \
    server/examos-server &

# Run specific test manually
bash tests/p3/attestation-suite.sh
```
