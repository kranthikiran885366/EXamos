# SPPIO Virtual Hardware Validation

This suite runs software-only checks in an isolated WSL/Linux workspace. It
does not replace the physical hardware qualification process.

## Run the suite

From PowerShell:

```powershell
wsl --exec bash '/mnt/d/SEB BRO/tests/virtual-hardware/run-all.sh'
```

The runner creates a new directory at
`tests/virtual-hardware/evidence/<run-id>/`. It refuses to reuse an existing
run directory. The inventory, reports, logs, virtual TPM state, UEFI variables,
and qcow2 overlay are kept per run. Generated evidence is excluded from Git
because it can contain VM state and large binary artifacts.

The selected raw disk is opened only as the read-only backing image of a
qcow2 copy-on-write overlay. By default, the VM harness uses the same output
directory as `scripts/build-image.sh`; on WSL with the repository on DrvFS,
that is `$HOME/.local/share/examos/images/examos.raw`, not the potentially
stale `image/examos.raw`. Set `EXAMOS_VH_IMAGE` to an absolute path to select a
specific raw image. The VM manifest records the selected path and its SHA-256;
the image remains a read-only backing file and QEMU writes only to the
run-specific overlay.
For interactive boot diagnosis, `EXAMOS_VH_DISPLAY=gtk` opens a local QEMU
display. `EXAMOS_VH_DISPLAY=vnc` binds a temporary VNC diagnostic display only
to `127.0.0.1` for framebuffer capture. These modes explicitly attach a
standard VGA device; the normal automated run remains headless. VNC mode is
blocked before startup if the installed QEMU build lacks its VNC backend.
In WSL, automatic acceleration uses TCG: this host exposed `/dev/kvm`, but the
KVM guest stayed running without producing serial output, while TCG reached
systemd. Outside WSL, KVM is attempted when available; a failed KVM launch
falls back to TCG unless KVM was explicitly required with
`EXAMOS_VH_ACCEL=kvm`. Set `EXAMOS_VH_ACCEL=tcg` to request TCG explicitly.
The guest includes a virtual xHCI controller so USBGuard exercises the normal
USB sysfs path. The kiosk unit requires the mandatory startup preflight, and
the QEMU gate rejects preflight or USBGuard failures rather than accepting a
browser-only readiness marker.

During guest boot, swtpm exposes one private UnixIO socket to QEMU. This is the
socket mode supported by QEMU's emulator TPM backend in this environment. The
host does not issue TPM commands before firmware starts the guest TPM. After
the guest reports stable kiosk readiness, the test stops QEMU, saves swtpm's
volatile PCR state, and restarts the same TPM state with paired private
UnixIO data/control sockets for TPM tools. The tools then query and quote the
post-boot PCRs without racing QEMU. No network endpoint is exposed. The socket
directory is removed after QEMU and swtpm stop. VM manifests using the previous
TCP control-channel schema must be reset to a new epoch before they can be
started by this harness.
After a guest reports stable kiosk readiness, the QEMU test requires a further
30-second stability interval with no Chromium signal exit or Crashpad startup
failure before saving the TPM's volatile state and querying its post-boot PCRs.
This prevents TPM-tool requests from racing the running guest while preserving
that boot's PCR state for the quote. The interval can be set with
`EXAMOS_VH_KIOSK_STABILITY_SECONDS` from 10 to 120 seconds.

The database test creates a new, non-root, loopback-only PostgreSQL cluster in
`/tmp` with temporary TLS credentials and a private connection file. It first
calls the backend's real database pool and base-schema initialization path,
then verifies every migration file is present in the explicit registry and
applies and reruns those registered migrations. It subsequently exercises auth CRUD,
rollback, restart persistence, and attestation-table tests against that
disposable cluster only, then removes only that newly created temporary
cluster. It never reads the configured production database URL. The integration
also starts a loopback-only development server against the disposable database
and uses an isolated `swtpm` to test device registration/read-back, duplicate
and malformed-AK rejection, and fail-closed attestation-challenge rejection
when no approved release is provisioned. Registration is not evidence of
trusted identity, a successful attestation, Secure Boot, or physical TPM use.
The rollback check verifies PostgreSQL transaction rollback after a deliberate
SQL error. The migration runner has no down-migration operation, so the suite
does not claim reversible schema migrations.

## Coverage without duplicate suites or substituted success

The runner uses one offline TPM ceremony regression for the
MakeCredential/ActivateCredential workflow; it does not also run the separate
credential-activation smoke script. The standalone swtpm quote test validates
the backend quote parser and rejection cases. The QEMU test has a different
purpose: quote the PCRs from the actual virtual guest boot. Neither result
stands in for physical TPM evidence.

The PostgreSQL run first invokes the backend's `db_init` and
`db_create_schema`, then the production migration executable against that
same disposable database. Migration errors are retained as failures; the test
does not patch the schema or skip migrations to manufacture a pass. Existing
production database environment variables are cleared, and both backend and
migrator connection paths are pinned to the private disposable connection
file.

The existing raw image and production services are never booted or contacted
directly. QEMU writes only to a run-specific qcow2 overlay, with networking
disabled. If an actual guest boot cannot be observed, the report records the
failure or blocked state instead of claiming boot success.

## VM lifecycle

After a run has created VM state, lifecycle scripts require an explicit
`EXAMOS_VH_RUN_DIR` pointing below `tests/virtual-hardware/evidence/`:

```bash
export EXAMOS_VH_RUN_DIR="/mnt/d/SEB BRO/tests/virtual-hardware/evidence/<run-id>"
bash tests/virtual-hardware/scripts/check-vm.sh
bash tests/virtual-hardware/scripts/stop-vm.sh
bash tests/virtual-hardware/scripts/reset-test-vm.sh
```

Reset creates a new numbered state epoch. It does not erase the previous
overlay, TPM state, UEFI variables, logs, or evidence. No script clears a
physical TPM or changes host firmware.

## Evidence and status meanings

Each run contains:

- `reports/phase0-inventory.md` and `reports/phase0-inventory.json`
- `reports/toolchain-inventory.md` and `reports/toolchain-inventory.json`
- `reports/phase3-summary.md` and `reports/phase3-summary.json`
- `reports/phase3-test-results.json`
- `reports/phase3-security-findings.md`
- `reports/phase3-limitations.md`
- `reports/phase3-physical-validation-checklist.md`
- `evidence-sha256.txt`

`PASS` means a test actually ran and its positive and negative outcomes were
checked. Missing prerequisites are `BLOCKED`, not a pass. Evidence hashes
support later comparison but do not make files immutable.

The suite distinguishes:

- software-emulated TPM (`swtpm`) from physical TPM hardware;
- UKI artifact signature validation from actual OVMF Secure Boot enforcement;
- dm-verity regular-file integrity checks from read-only root mounting and
  boot integration;
- TPM PCR reads/quotes from an independently reconstructed TCG event log;
- a disposable local PostgreSQL integration test from production database
  access.

No test-signed key is enrolled into production firmware or accepted as
organization approval. A software TPM can never qualify a device for
production hardware enrollment.

## Known environment limitations

WSL cannot validate physical firmware or physical TPM behavior. `systemd-measure`,
ShellCheck, and Bats were absent in the audited environment. Their absence is
reported; the suite does not install packages. The current disk boot profile
uses systemd-boot, while the repository's dm-verity setup is host-side artifact
generation and does not bind the generated root hash into the running boot
chain. The suite does not silently rewrite that production image architecture.
