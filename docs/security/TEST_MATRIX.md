# ExamOS test matrix

Verdicts: PASS | FAIL | BLOCKED | NOT TESTED. Never convert skipped/synthetic into PASS.

| ID | Class | Property | Harness | Mode | Last result |
|----|-------|----------|---------|------|-------------|
| P3-QUOTE | Integration / negative | TPM quote signature, AK name, nonce, selected PCR digest, tamper rejection | `tests/p3/swtpm-quote-smoke.sh` | swtpm | PASS in current development run; software TPM only |
| P3-REGISTRY | Integration / tamper negative | Signed production registries and complete AK binding | `tests/p3/production-registry.sh` | ephemeral signing keys, production mode | PASS in current development run; not an organization signing ceremony |
| P3-LEGACY-SUITE | Retired | Synthetic quote signatures | `tests/p3/attestation-suite.sh` | none | BLOCKED; cannot provide attestation evidence |
| P3-HMAC | Config | Missing production HMAC key | `tests/p3/startup-fail-closed.py` | production | Adding this increment |
| P3-TOFU | Negative | Enrolled AK required when names present | `tests/p3/production-registry.sh` | development with signed fixtures | PASS current registry cases |
| P3-EK | Integration | Test CA verifies EK leaf | `tests/production/trust-provisioning-gate.sh` | production inputs | BLOCKED; organization EK trust assets unavailable |
| P3-GO | Unit | Empty golden PCR must FAIL | verifier.go | development | Code fix this increment |
| P3-EVENTLOG | Negative | TCG replay | none | — | NOT TESTED / not implemented |
| P3-HW | Hardware | Physical quote + server nonce | `hardware-tpm-preflight.sh` | physical | NOT TESTED this increment |
| P3-EVENTLOG-REPLAY | Unit / malformed negative | SHA-256 TCG2 event-log replay and PCR extension | `tests/p3/test-eventlog-replay.py` | synthetic structural fixture | PASS Oct 11; raw hardware log and quote binding NOT TESTED |
| P3-REGISTRY | Integration / tamper negative | Signed production registries and complete AK binding | `tests/p3/production-registry.sh` | ephemeral signing keys, production mode | PASS Oct 11; not an organization signing ceremony |
| BOOT-EVIDENCE | Artifact/evidence | UKI signature, command line, verity rootfs/tree and raw event-log package | `tests/production/collect-boot-chain-evidence.sh` | release candidate inputs | BLOCKED Oct 11: release UKI, DB certificate, verity artifacts and raw log absent |
| P0-BOOT | VM | QEMU/OVMF disk boot | `tests/p0/boot.sh` | VM | VM-only; dirty provenance |
| P2-GUEST | VM | nftables/USB/verity live | `p2-guest-integration.sh` | VM | NOT_RUN / BLOCKED historically |
| P2-VERITY | Fault | Tamper reject | `p2-verity-tests.sh` | — | NOT TESTED as live boot |
| SB-NEG | Negative | Unsigned UKI refused | firmware VM | VM | NOT TESTED |
| PHYS-A | Read-only | Dell firmware/TPM/BitLocker inspect | PHYSICAL_DEVICE_TEST_PLAN | physical | NOT TESTED |
| PHYS-C | External boot | USB only after identity approval | — | physical | NOT TESTED; approval required |

## Evidence rules

Each run records: git commit, dirty/clean, `EXAMOS_TPM_MODE`, artifact dir, tool versions, SHA-256 of outputs. Isolate mutable state under that artifact dir. Do not overwrite `artifacts/p3/evidence-packages/examos-p3-results.BToS4h-20261011T053619Z`.
