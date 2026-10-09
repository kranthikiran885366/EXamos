# ExamOS Phase 4 — Proctoring and Tamper-Evident Architecture

## 1. Overview
ExamOS Phase 4 introduces an automated proctoring and tamper-evident evidence capture system built directly upon the validated P0–P3 trusted base. The architecture maintains a strict separation between the **Media Plane** and the **Evidence Plane**.

## 2. Core Architecture Pipeline
```text
Candidate Browser (WebRTC)
      |
      +--> Candidate Consent Modal
      |
      +--> Primary Camera & Microphone Capture (Origin-Bound)
      |
      v
Analysis Engine (Native Vision Worker)
      |
      +--> Face Detection & Face Count (1, >1, 0)
      +--> Head-Pose Estimation (Yaw, Pitch, Roll)
      +--> Object Detection (Phones, Books)
      |
      v
Normalized Proctoring Events (JSON)
      |
      v
Event Ingestion Engine (Port 8000/9099)
      |
      v
Tamper-Evident Hash Chain (SHA-256 Chaining)
      |
      +--> Append-Only Log: /var/log/examos/proctoring_events.log
      +--> Periodic Cryptographic Checkpoint Signatures
      |
      v
Independent CLI Verifier (exam-event-verify)
```

## 3. Guiding Security Principles
1. **Never Send Raw Video to Risk Engine**: Raw video streams are processed exclusively by the local/edge analysis worker. Only normalized, structured detection signals enter the audit pipeline.
2. **Deterministic Canonical Serialization**: All events follow strict canonical JSON representation prior to SHA-256 hash generation.
3. **Multi-Source Video Binding**: Second cameras (mobile phone desk/room view) pair through short-lived, one-time QR tokens strictly bound to the authenticated examination session.
4. **Independent Verification**: An independent standalone CLI verifier (`exam-event-verify`) can audit the entire hash chain offline.
