# ExamOS — Prevention-First Secure Operating System

ExamOS is a **Linux examination-appliance development prototype** written in native C and C++.

> **Status: development prototype.**
> Current evidence is mixed and is not a release certificate: a P0 image build
> and QEMU serial boot are recorded, P1 fails, P2 has not run its mandatory
> tests, the P3 aggregate result is invalidated (a separate 18/18 swtpm suite
> artifact is not a release result), P4 is invalidated, and P5/P6 are blocked.
> **Do not use this build for live exams or
> treat its telemetry as trusted.** See
> [the current end-to-end audit](docs/security/END_TO_END_AUDIT.md) and
> [the TCS iON NQT comparison](docs/security/TCS_NQT_COMPARISON.md).

---

## Phase Status

| Phase | Description | Gate |
|-------|-------------|------|
| **P0** | Foundation build, QEMU/OVMF boot | **BLOCKED** (current disk build is `c0b4619a…997b00af`; recorded disk boot and first-boot PASS results bind to the older `a531ad41…1361de3f`; current ISO optical boot FAILs with QEMU exit 139; source is dirty; physical and production trust are not proven) |
| **P1** | Kiosk + network configuration | **FAIL** (`artifacts/p1/results.json`: artifact and guest boot checks fail; exam URL and performance are blocked) |
| **P2** | OS lockdown — nftables, AppArmor, USBGuard, dm-verity, module lock | **NOT RUN** (20 mandatory tests are recorded not-run; runtime/hardware behavior is unverified) |
| **P3** | TPM attestation + exam-key release | **INVALIDATED** (aggregate `artifacts/p3/results.json` is invalidated; separate 18/18 swtpm suite artifact is dirty-tree development evidence only) |
| **P4** | Proctoring engine + tamper-evident event chain | **INVALIDATED** (prior detection-quality claim used fabricated evidence; regression failed; real labelled dataset and packaged model pipeline are absent) |
| **P5** | Candidate behavior, viva and human review | **BLOCKED** (P5-A–E pass their recorded tests; P5-F–H and P5-I are blocked) |
| **P6** | Production prerequisites and release readiness | **BLOCKED** (phase evidence, hardware matrix, red-team, pilot and key-custody prerequisites are unmet) |

### Known Prototype Limitations

1. **Attestation is not production-certified.** The C server contains a
   `TPMS_ATTEST` parsing and AK-signature verification path and the recorded
   development suite passed with `swtpm`; no physical TPM acceptance evidence
   exists. TCG event-log replay, production trust-registry provisioning, and
   hardware-backed key custody still require implementation/verification.

2. **P2 has never been dynamically validated.** Firewall allow/deny, dm-verity
   corruption rejection, USB hardware enforcement, and runtime kernel-hardening
   checks have never run inside a booted ExamOS guest. All current P2 evidence
   is static configuration inspection only.

3. **The server speaks plaintext HTTP.** It defaults to loopback and refuses a
   non-loopback bind unless `EXAMOS_TLS_TERMINATED=1`; that setting does not
   itself prove a proxy is present or correctly configured. No TLS/mTLS
   termination deployment is included here.

4. **Credentials are deployment-provisioned, not image defaults.** The image
   contains no admin or candidate credential records. Production services
   require externally provisioned agent/proctor tokens and signed trust
   registries, and fail closed when those inputs are absent. Enterprise
   identity, MFA, brute-force protection, and account lockout are not
   implemented.

5. **Persistence is not production-grade.** Some session and ledger state has
   file-journal support; attestation state and exam data are not backed by a
   validated transactional, replicated, backup-tested storage service.

6. **Proctoring is not certifiable.** OpenCV DNN model support is conditional
   in the source, but the current proctor build does not enable/link it or
   provision model files. The previous P4 metrics are invalidated; no real
   labelled evaluation dataset is present. Gaze and liveness are not
   production-validated.

7. **Boot-to-kiosk is not conclusively demonstrated.** The P1 gate validates
   static configuration files. A real end-to-end boot into a locked Chromium
   kiosk on target hardware has not been proven.

8. **Security issue blocks production.** The historical AK-name shell
   injection was fixed by fixed-argument process execution and strict input
   validation, with a regression test recorded in the issue register. This
   does not establish physical TPM activation or production trust; see the
   end-to-end audit for remaining attestation and transport blockers.

---

## Architecture Overview

```text
ExamOS Linux Base Image (Debian Trixie, mkosi, Secure Boot UKI, systemd-boot)
                          │
    ┌─────────────────────┼────────────────────┐
    │                     │                    │
 Kiosk Launcher       Security Agent      Proctoring Engine
 (kiosk/, C)          (agent/, C)         (proctoring/, C++)
 Cage/Wayland          TPM PCR read        V4L2 camera
 Chromium kiosk        Hardware guard       Optional OpenCV DNN models (not packaged/enabled in current build)
 Ephemeral profile     RF scanner          Event hash chain
    │                     │                    │
    └─────────────────────┼────────────────────┘
                          │
              ExamOS Server (server/, C)
              Raw POSIX HTTP/1.1, port 8000
              Attestation + Ledger + Exam engine
```

---

## Building

```bash
# Build all native C/C++ binaries
make all

# Build + run P3 test suite
make p3-gate

# Clean build artifacts
make clean
```

---

## OS Image

```bash
# Verify host readiness
bash scripts/examos-doctor.sh

# Build minimal Debian Trixie disk image
cd image && sudo mkosi build

# Launch in QEMU with UEFI
bash scripts/run-qemu.sh
```

---

## Phase 3 Quick Start (Attestation)

```bash
# Source P3 environment config (sets all required env vars)
source image/config/p3.conf

# Generate development Secure Boot test keys
bash image/trust/generate-dev-keys.sh

# Build server + Go verifier
make p3

# Run the development attestation test suite (not production certification)
bash tests/p3/gate.sh
```

---

## Repository Layout

```
agent/          Security agent (TPM, hardware guard, heartbeat, RF scanner)
server/         HTTP server (attestation, exam engine, ledger, admin)
kiosk/          Chromium kiosk supervisor (Cage/Wayland)
proctoring/     Camera proctoring engine (V4L2, vision, event chain)
tools/          Standalone CLI tools (exam-event-verify)
image/          OS image build (mkosi.conf, overlay, scripts, trust keys)
scripts/        Build and maintenance scripts
tests/          Phase test suites (p0–p6, phase4, production)
artifacts/      CI output and phase-gate evidence (mixed validity)
docs/           Architecture, phase gates, end-to-end audit, production gaps
.github/        CI workflows (p0.yml, p1.yml, p2.yml, p3.yml)
```
