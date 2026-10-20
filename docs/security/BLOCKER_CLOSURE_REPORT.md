# Production blocker-closure report

**Status:** not production ready. This report records implemented controls and
the external evidence that source changes cannot create.

| Blocker | Implementation / test | Current result | Remaining production evidence |
|---|---|---|---|
| Signed production registries | `attestation_config.c`; `tests/p3/production-registry.sh` | PASS for valid signed ephemeral registries and tamper/incomplete-entry rejection | Organization-owned trust anchors, signing ceremony, signed release/device records |
| EK/AK enrollment and quote validation | C attestation service validates EK chain, AK binding, TPMS_ATTEST nonce/PCR and signature; credential-activation smoke | Development/software TPM coverage only | Manufacturer EK chain and authorized physical-device enrollment |
| Event-log replay | `tools/examos-eventlog-replay.py`; `tests/p3/test-eventlog-replay.py` | PASS for supported TCG2 SHA-256 fixtures; malformed/truncated logs fail closed | Raw physical event log replayed and bound to quote/PCR evidence |
| Secure Boot / UKI / dm-verity | `tests/p2/p2-secureboot-gate.sh`, `tests/production/collect-boot-chain-evidence.sh`, verity corruption tests | Oct 11 isolated gate FAIL: the available UKI lacks `lockdown=confidentiality`; collector correctly BLOCKED with no supplied release inputs | Approved signing identity, release UKI with bound verity root hash, OVMF positive/negative evidence, then external-device proof |
| P4 model/data governance | `tests/phase4/model-governance.py`; invoked before P4 quality evaluation | BLOCKED without external manifest, model binaries, licences, consented labels | Approved inventory/licence files, consent/retention/annotation evidence, independent evaluation |

Software TPM, synthetic fixtures, VM runs, and ephemeral test signing keys are
not hardware or production evidence. Hardware work remains restricted to the
approved external-device process in `PHYSICAL_DEVICE_TEST_PLAN.md`.

The seven external blockers are executed by `scripts/production-readiness.sh`.
That aggregator records BLOCKED/FAIL honestly; it does not promote QEMU,
swtpm, or development keys to production PASS.
