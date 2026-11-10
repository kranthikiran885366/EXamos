# ExamOS Phase 4 — Architecture Audit and Integration Plan

## 1. Executive Summary
ExamOS Phase 4 introduces a prevention-first, tamper-evident examination proctoring pipeline. The architecture extends the frozen Phase 0–Phase 3 foundation (UEFI, Secure Boot, Signed UKI, TPM 2.0 Attestation, Cage/Wayland kiosk, hardened network/USB/sysctl, and native security server) without weakening or bypassing any existing control.

## 2. Component Integration Matrix

| Component | Current P0–P3 Implementation | Phase 3 Dependency | Phase 4 Integration Point | Files Modified / Added | Security Assumptions |
|---|---|---|---|---|---|
| **Kiosk & Browser** | Cage Wayland + Chromium kiosk profile | Restricted exam URL | WebRTC media permission restricted strictly to exam origin, in-browser consent flow | `server/login/candidate_login.c`, `image/overlay/etc/apparmor.d/examos-kiosk` | Camera/mic blocked outside exam origin |
| **Server Engine** | Native C multi-threaded HTTP server | Session & token management | WebRTC signaling, event ingestion, second-camera QR pairing, retention control | `server/main.c`, `server/include/event_chain.h`, `server/events/event_chain.c` | Port 8000/9099 default-deny firewall allowlisted |
| **Analysis Worker** | `examos-proctor` native C++ binary | V4L2 device enumeration | Real frame sampling, face count, no-face, head pose estimation, phone/book detection | `proctoring/main.cpp`, `proctoring/analysis/vision_engine.cpp`, `proctoring/include/vision_engine.h` | Emits normalized events, never raw video |
| **Event Store** | Hash-chained event ledger | Append-only SHA-256 block ledger | Structured proctoring event schema, SHA-256 hash chaining, periodic signing | `server/events/event_chain.c`, `server/include/event_chain.h` | Strict `UNIQUE(sessionId, sequence)` ordering |
| **Tamper Verifier** | Runtime ledger validation | SHA-256 block verification | Independent standalone CLI tool `exam-event-verify` | `tools/exam-event-verify.c` | Verifies hash continuity and signature integrity |
| **Second Camera** | N/A | Session ID & device binding | Short-lived QR token pairing, secondary WebRTC desk/room feed | `server/proctoring/second_camera.c`, `server/include/second_camera.h` | One-time token, non-reusable across sessions |

## 3. Media vs. Evidence Separation Principle
- **Media Plane**: Transports encrypted audio/video between the candidate browser/second camera and the analysis worker.
- **Evidence Plane**: Receives structured, normalized detection signals (`FACE_PRESENT`, `MULTIPLE_FACES`, `NO_FACE`, `HEAD_POSE`, `PHONE_DETECTED`, `BOOK_DETECTED`).
- **Zero Raw Video to Risk Engine**: Raw video streams are never piped into the risk engine or event database.

## 4. Hash Chaining and Cryptographic Checkpoint Signing
- **Genesis Block**: `previousHash = 0000000000000000000000000000000000000000000000000000000000000000`
- **Hash Formula**: `eventHash = SHA256(previousHash || canonicalJSON(event))`
- **Canonical Serialization**: Deterministic key sorting, ISO 8601 UTC timestamps, fixed floating-point precision.
- **Checkpoint Signatures**: Server periodically signs the latest event hash with an RSA/ECDSA key.

## 5. Security Boundary Verification
- All P0–P3 gates remain fully intact and active.
- Device attestation and release verification remain required prior to exam session authorization.
- USB mass storage, shell access, SSH, and unprivileged user logins remain disabled.
