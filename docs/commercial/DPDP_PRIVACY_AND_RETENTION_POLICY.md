# SPPIO / ExamOS — Privacy & Data Retention Policy (India DPDP Act Aligned)

## 1. Scope & Roles
This policy governs personal data processed during proctored examinations and technical assessments under the **Digital Personal Data Protection Act, 2023 (DPDP Act)**:
- **Data Fiduciary**: The administering Institution / University / Enterprise.
- **Data Processor**: SPPIO Systems Enclave (`sppio-core` & station runtime), acting strictly on the Data Fiduciary's configured exam policy.

## 2. Explicit Consent Before Monitoring
- Before any webcam, microphone, or RF/environment telemetry starts, the SPPIO workstation presents an **explicit on-screen consent notice** (`e1_consent`) detailing what signals are captured, the purpose (examination integrity), and the retention window.
- Raw video streams are analyzed **on-device** by `examos-proctor`; raw video is not streamed off-premise by default.

## 3. Data Minimization & Purpose Limitation
- **Hardware Telemetry**: TPM PCRs, IMA digests, USB/display state, and sanitized diagnostics (`examos-diag-bundle.sh` redacts MACs, IPs, and emails).
- **Proctoring Events**: Structured detection metadata (`FACE_PRESENT`, `MULTIPLE_FACES`, `PHONE_DETECTED`) signed into the tamper-evident ledger.

## 4. Configurable Retention & Auto-Deletion
Institutions configure retention windows per examination policy:
- **Transient Station Buffers**: Wiped in RAM/tmpfs immediately at session end; offline WAL (`offline-events.wal`) is purged as records sync.
- **Proctoring & Telemetry Metadata**: Default **30–90 days** post-result publication (configurable per institution), followed by automated purge.
- **Audit & Compliance Ledger**: Retained per statutory / university examination-board mandate with cryptographic hash chaining.

## 5. Data Principal Rights
Candidates may exercise rights of access, correction, and erasure through their administering Institution's Examination Controller / Data Protection Officer, who can trigger institution-scoped exports or deletion workflows in the SPPIO console.
