# Secure Physical Proctoring and Isolation OS (SPPIO™)

**SPPIO™** (*Secure Physical Proctoring and Isolation OS*) is an enterprise-grade, prevention-first Linux examination-appliance and continuous trust verification platform written in native C, C++, and modern React.

> **Status: Development Prototype.**  
> Current evidence is mixed and is not a release certificate: a P0 image build and QEMU serial boot are recorded, P1 fails, P2 has not run its mandatory tests, the P3 aggregate result is invalidated (a separate 18/18 swtpm suite artifact is not a release result), P4 is invalidated, and P5/P6 are blocked.  
> **Do not use this build for live exams or treat its telemetry as trusted.** See [the current end-to-end audit](docs/security/END_TO_END_AUDIT.md) and [the TCS iON NQT comparison](docs/security/TCS_NQT_COMPARISON.md).

---

## 🏛️ SPPIO™ Brand Architecture & Module Map

| Subsystem Identifier | Brand Module Name | Core Technology Stack | Primary Purpose | Repository Path |
| :--- | :--- | :--- | :--- | :--- |
| **Module 1** | **SPPIO-Isolation™ Base OS** | Debian Trixie, UKI, `systemd-boot`, `dm-verity`, `nftables` | Hardened, read-only, ephemeral Linux appliance environment | `image/`, `image/overlay/` |
| **Module 2** | **SPPIO-PhysicalGuard™** | ISO C11, `USBGuard`, DRM/KMS, Netlink / `iw` | Physical device guard: USB lockout, multi-display & RF detection | `agent/` |
| **Module 3** | **SPPIO-Proctor™ (Vision Engine)** | ISO C++17, OpenCV 4, V4L2, Haar Cascade, MobileNet DNN | Autonomous edge proctoring: facial presence, head pose, contraband | `proctoring/` |
| **Module 4** | **SPPIO-Kiosk™ Sandbox** | Wayland / `Cage`, Chromium Enterprise, `tmpfs` | Isolated, distraction-free browser kiosk in volatile RAM | `kiosk/` |
| **Module 5** | **SPPIO-TrustEngine™** | TPM 2.0 (`TPMS_ATTEST`), PCR 0/4/7/11, AES-256-GCM | Cryptographic hardware attestation & ephemeral key release | `server/attestation/` |
| **Module 6** | **SPPIO-Ledger™** | HMAC-SHA256, Monotonic Anchors, Merkle Chaining | Tamper-evident, court-admissible audit log & offline verification | `server/events/`, `tools/` |
| **Module 7** | **SPPIO-Forensics™** | Zero-Width Steganography, LLM Viva Evaluation | Leak attribution watermarking & conversational knowledge validation | `server/behaviour/` |
| **Module 8** | **SPPIO-Core™ Server** | Native POSIX C, OpenSSL 3.0+ TLS, PostgreSQL 16 | High-throughput backend engine, exam lifecycle & fleet state | `server/` |
| **Module 9** | **SPPIO-Command™ Console** | React 18.3, Vite 5.4, React Router 6, Web Crypto | Multi-tenant cloud & campus administrative and proctoring portal | `frontend/` |

---

## 🏗️ System Architecture

```text
                           SPPIO™ ECOSYSTEM TOPOLOGY
                     
      [ Candidate Appliance ]                           [ Central Infrastructure ]
 ┌──────────────────────────────────┐             ┌────────────────────────────────────┐
 │  SPPIO-Isolation™ Base OS (Debian)│             │ SPPIO-Core™ Server (Native C)      │
 │  ├── SPPIO-Kiosk™ (Cage/Chromium)│  mTLS /     │  ├── SPPIO-TrustEngine™ (TPM 2.0)  │
 │  ├── SPPIO-PhysicalGuard™ (Agent)│  REST API   │  ├── SPPIO-Ledger™ (HMAC Audit)    │
 │  └── SPPIO-Proctor™ (C++ Vision) │ ──────────> │  └── PostgreSQL 16 Encrypted Store │
 └──────────────────────────────────┘             └──────────────────┬─────────────────┘
                                                                     │
                                                  ┌──────────────────┴─────────────────┐
                                                  │ SPPIO-Command™ Console             │
                                                  │ (React 18 / Vite Enterprise Portal)│
                                                  └────────────────────────────────────┘
```

---

## 💻 Complete Technology Stack Compilation

### 1. Endpoint & Operating System (`SPPIO-Isolation™`)
* **Distribution Base:** Minimal Debian GNU/Linux 11/13 (Trixie) appliance.
* **Boot Chain:** UEFI Secure Boot (PK, KEK, db) $\rightarrow$ `systemd-boot` $\rightarrow$ Unified Kernel Image (UKI).
* **Disk Integrity:** Linux `dm-verity` cryptographically verified read-only root filesystem.
* **Kernel Security:** Kernel lockdown (`lockdown=confidentiality`), module signing (`CONFIG_MODULE_SIG_FORCE`), AppArmor, strict sysctl tunings (`kptr_restrict=2`, `protected_fifos=2`).
* **Perimeter Defense:** Linux `nftables` default-deny firewall (restricting traffic strictly to authorized server endpoints).

### 2. Physical & Hardware Guard (`SPPIO-PhysicalGuard™`)
* **Core Language:** Pure ISO C (C11 / GNU99).
* **Peripheral Lockdown:** `USBGuard` daemon with white-list rules prohibiting mass storage and unauthorized HID inputs.
* **Display Sandboxing:** Direct DRM/KMS interrogation via `/sys/class/drm/` to detect and reject secondary screens or virtual display devices.
* **RF Spectrum Supervision:** Netlink / `iw dev scan` and `/proc/net/wireless` parsing to block ad-hoc networks and tethering.
* **Process Watchdog:** 5-second polling loop reading `/proc/*/comm` against unauthorized debugging and screencasting tools (`gdb`, `wireshark`, `obs`, `teamviewer`, `rustdesk`).

### 3. Edge Computer Vision Proctoring (`SPPIO-Proctor™`)
* **Core Language:** ISO C++17.
* **Video Capture:** Linux Video4Linux2 (`V4L2`) raw frame grabber.
* **Vision & Machine Learning:** OpenCV 4 (`libopencv_core`, `libopencv_imgproc`, `libopencv_objdetect`, `libopencv_dnn`).
* **Detection Models:** Haar Cascades, Caffe SSD, MobileNet SSD (contraband & device detection), 68-point landmark head pose estimation.
* **Event Dispatch:** Asynchronous HTTPS telemetry transmission via `libcurl`.

### 4. Sandbox Kiosk Supervisor (`SPPIO-Kiosk™`)
* **Display Server:** Wayland protocol via `Cage` lightweight kiosk compositor.
* **Browser Sandbox:** Chromium Enterprise locked with `--kiosk`, `--incognito`, WebRTC restrictions, and extension blacklists.
* **Volatile Storage:** Ephemeral user session mounted in RAM (`tmpfs`) cryptographically shredded on exit.

### 5. Hardware Attestation Engine (`SPPIO-TrustEngine™`)
* **Hardware Module:** TPM 2.0 (Trusted Platform Module).
* **Measurements:** PCR 0 (BIOS), PCR 4 (Bootloader), PCR 7 (Secure Boot), PCR 11 (OS Container / UKI).
* **Cryptographic Verification:** Binary `TPMS_ATTEST` quote parser, Attestation Key (AK) signature checks, and dynamic challenge nonces.
* **Key Release:** AES-256-GCM exam encryption keys sealed and released strictly to trusted hardware quotes.

### 6. Non-Repudiable Event Ledger (`SPPIO-Ledger™`)
* **Integrity:** HMAC-SHA256 authenticated event chain with monotonic `.anchor` files preventing truncation or history rewriting.
* **Verification Utility:** Standalone CLI tool `tools/exam-event-verify` for independent audits.

### 7. Behavioral Forensics & Watermarking (`SPPIO-Forensics™`)
* **Steganographic Watermarking:** Zero-width Unicode sequences (`\u200B`, `\u200C`, `\u200D`) injected into question texts for candidate leak attribution.
* **Conversational Viva:** Post-exam viva engine cross-referencing candidate answers via structured verification probes.

### 8. Enterprise Core Backend (`SPPIO-Core™`)
* **HTTP Engine:** Native POSIX C multi-threaded socket engine with OpenSSL 3.0+ TLS termination.
* **Database & Persistence:** PostgreSQL 16 with native `libpq` connection pooling.
* **Authentication:** SCRAM-SHA-256 database protocol, PBKDF2/Argon2 password hashing, and RFC 6238 TOTP MFA.
* **Schema Evolution:** 15 modular SQL migrations governing institutional hierarchies, exams, question banks, candidate rosters, and fleet inventories.

### 9. Enterprise Web Console (`SPPIO-Command™`)
* **Frontend Architecture:** React 18.3.1 SPA powered by Vite 5.4.8 and React Router DOM 6.26.2.
* **Security & Auth:** Web Crypto API request signing, TOTP QR code generator, and role-based route guard rails.
* **Portals:** Institution & Campus Hub, Fleet & Hardware Monitor, Proctor Operations Desk, and Candidate Exam Workbench.

---

## 🚦 Phase Status

| Phase | Description | Gate |
|---|---|---|
| **P0** | Foundation build, QEMU/OVMF boot | **BLOCKED** (current disk build is `c0b4619a…997b00af`; recorded disk boot and first-boot PASS results bind to older `a531ad41…1361de3f`; optical ISO boot FAILs with QEMU exit 139) |
| **P1** | Kiosk + network configuration | **FAIL** (`artifacts/p1/results.json`: artifact and guest boot checks fail; exam URL and performance are blocked) |
| **P2** | OS lockdown — nftables, AppArmor, USBGuard, dm-verity, module lock | **NOT RUN** (20 mandatory tests recorded not-run; runtime/hardware behavior is unverified) |
| **P3** | TPM attestation + exam-key release | **INVALIDATED** (aggregate `artifacts/p3/results.json` is invalidated; separate 18/18 swtpm suite artifact is dirty-tree development evidence only) |
| **P4** | Proctoring engine + tamper-evident event chain | **INVALIDATED** (prior detection-quality claim used fabricated evidence; regression failed; real labelled dataset and packaged model pipeline are absent) |
| **P5** | Candidate behavior, viva and human review | **BLOCKED** (P5-A–E pass recorded tests; P5-F–H and P5-I are blocked) |
| **P6** | Production prerequisites and release readiness | **BLOCKED** (phase evidence, hardware matrix, red-team, pilot and key-custody prerequisites are unmet) |

---

## 🛠️ Building & Development

### Build Native C/C++ Subsystems
```bash
# Build all native C/C++ binaries (SPPIO-Kiosk, SPPIO-PhysicalGuard, SPPIO-Proctor, SPPIO-Core)
make all

# Clean build artifacts
make clean
```

### Build Enterprise Web Console (`SPPIO-Command™`)
```bash
cd frontend
npm install
npm run build
```

### Build Operating System Image (`SPPIO-Isolation™`)
```bash
# Verify host readiness
bash scripts/examos-doctor.sh

# Build minimal Debian Trixie disk image
cd image && sudo mkosi build

# Launch in QEMU with UEFI
bash scripts/run-qemu.sh
```

### Run Hardware Attestation Test Suite (`SPPIO-TrustEngine™`)
```bash
# Source environment config
source image/config/p3.conf

# Generate development Secure Boot test keys
bash image/trust/generate-dev-keys.sh

# Build server + Go verifier
make p3

# Run the development attestation test suite (not production certification)
bash tests/p3/gate.sh
```

---

## 📁 Repository Layout

```text
agent/          SPPIO-PhysicalGuard™: Client security agent (TPM, hardware guard, heartbeat, RF scanner)
server/         SPPIO-Core™: Native C HTTP server (attestation, exam engine, ledger, admin)
kiosk/          SPPIO-Kiosk™: Chromium kiosk supervisor (Cage/Wayland)
proctoring/     SPPIO-Proctor™: Camera proctoring engine (V4L2, OpenCV vision, event chain)
frontend/       SPPIO-Command™: React 18 / Vite enterprise management and proctoring console
tools/          SPPIO-Ledger™ tools: Standalone CLI verification utilities (exam-event-verify)
image/          SPPIO-Isolation™: OS image build (mkosi.conf, overlay, scripts, trust keys)
scripts/        Build, maintenance, and orchestration scripts
tests/          Phase test suites (p0–p6, phase4, production)
artifacts/      CI output and phase-gate evidence
docs/           Architecture, phase gates, end-to-end audit, production readiness
.github/        CI workflows (p0.yml, p1.yml, p2.yml, p3.yml)
```
