# Test-only external dependency suite

Run the following from Linux or WSL after installing the applicable tools:

```bash
bash tests/test-only/run-external-dependency-tests.sh --simulate
```

It creates a unique result directory under `artifacts/test-only/runs/`. It
tests disposable software substitutes only: a `swtpm`, temporary registry
keys, TPM credential activation, event-log replay, dm-verity hash-tree
corruption rejection, USB policy fixtures, synthetic video fixtures, event
tamper/concurrency, and the deterministic Viva offline fallback.

The TPM attestation E2E, tamper, and concurrency portions start the local
server and need a **disposable** reachable PostgreSQL database. Provide its
connection string only through the environment (never commit it):

```bash
export EXAMOS_TEST_DATABASE_URL='postgresql://test-user:password@127.0.0.1:5432/examos_test'
bash tests/test-only/run-external-dependency-tests.sh --simulate
```

Without that variable, those three checks are correctly reported as
`BLOCKED`, not as product failures.

For your own physical-device check, use:

```bash
bash tests/test-only/run-external-dependency-tests.sh --physical
```

This runs the USB observation window and physical TPM preflight if their
hardware and tools are present. It does not enroll, clear, or otherwise alter
the TPM or UEFI firmware. Keep a USB mass-storage device ready for the USB
check.

`SIMULATED_PASS`, `PHYSICAL_PASS`, and `TEST_ONLY_PASS` are not release
evidence. The suite retains `MANUAL_REQUIRED` for hardware qualification,
independent red-team work, key custody, and pilot acceptance because software
cannot truthfully simulate those organizational controls.
