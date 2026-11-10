# SPPIO™ Phase 4.1 — Complete Repository and Architecture Audit Report

**Date:** 2026-11-10T04:55:00Z  
**Author:** Principal Software Architect, Linux Security Engineer & DevSecOps Lead  
**Scope:** Architecture, Route Inventory, API Inventory, Database Inventory, Existing Workflows, Duplicate Implementation Analysis, Security Findings, and Missing Functionality.

---

## 1. Product Scope & Architectural Foundations

SPPIO™ (**Secure Physical Proctoring and Isolation OS**) is an enterprise appliance and control plane designed specifically for:
- Secure device isolation and tamper-resistant operating system boot (ExamOS via UEFI, Secure Boot, UKI, dm-verity, and TPM 2.0).
- Institution accreditation, multi-tenant administrative management, and role-based access control.
- Candidate registration, verification, and credential issuance.
- **Individual Candidate-to-Examination URL Assignment and secure launch authorization.**
- Cryptographic TPM attestation and hardware trust binding.
- Session lifecycle tracking, peripheral blocking, and proctoring observability.
- Tamper-evident ledger auditing and compliance reporting.

### Explicit Scope Boundary (Section 1)
SPPIO **is NOT an examination management system**.
- **Excluded:** Question bank creation, question editing/upload, MCQs, answer key management, marks calculation, or internal test engines.
- **Authoritative Flow:** The institution or examination administrator supplies external HTTPS examination URLs (e.g., `https://sppio-os.vercel.app/candidate-login` or external institutional exam engines). SPPIO validates, authorizes, isolates, and securely launches the assigned external URL inside the locked-down ExamOS kiosk.

---

## 2. Route Inventory (Frontend)

Derived directly from `frontend/src/App.jsx` and `frontend/src/core/nav.js`:

### 2.1 Public & Unauthenticated Routes
- `/`: Public Landing Page
- `/landing`: Alternative Landing View
- `/architecture`: Technical Architecture Overview
- `/solutions`: Enterprise Solutions Showcase
- `/register-institution`: Public Institution Accreditation & Application Page
- `/login`: Administrative & Operator Staff Login
- `/candidate-login`: Dedicated Candidate Desk Login Portal
- `/mfa`: Multi-Factor Authentication Verification Step
- `/recovery`: Emergency Password & Account Recovery
- `/reset-password`: Administrator Password Reset
- `/invite/:token`: Administrator Onboarding Invitation Acceptance
- `/unauthorized`: 403 Forbidden Access Page
- `/expired`: Session Expiration Notice

### 2.2 Platform Admin (Superadmin & Ops)
- `/platform/institutions`: Global Tenant Overview
- `/platform/institutions/directory`: Institutional Directory & Tenant Grid
- `/platform/institutions/applications`: Verification & Accreditation Queue
- `/platform/provisioning`: Tenant Dedicated Provisioning
- `/platform/readiness`: Deployment Readiness & Pilot Evaluation
- `/platform/operations`: Global Platform Operations & Ledger Audit
- `/platform/institutions/:id`: Tenant Inspection & Management View

### 2.3 Institution Admin (College & University)
- `/institution/dashboard`: College Executive Metrics & Operational Status
- `/institution/settings/profile`: College Institutional Profile & Metadata
- `/institution/organization`: Campus, Center, and Department Hierarchy
- `/institution/settings/access`: Institutional Staff, Roles, and Permissions
- `/institution/settings/security`: Appliance Policy & Security Configuration
- `/institution/deployment`: Device Fleet Readiness & Rollout Overview
- `/institution/audit`: Tenant-Scoped Audit Log

### 2.4 Administration & Governance
- `/admin/institutions`: Institutional Administration
- `/admin/institution-applications`: Application Review Pipeline
- `/admin/users`: User Directory & RBAC Governance
- `/admin/roles`: Permission Matrix & Custom Role Definitions
- `/admin/approvals`: Centralized Multi-Party Approval Queue
- `/admin/settings`: Platform Configuration
- `/admin/system-health`: System Metrics, Socket Status, & Latency
- `/admin/audit`: Global Tamper-Evident Ledger Audit Trail
- `/admin/releases`: ExamOS Appliance Release Vault
- `/release-rollouts`: Phased Release Deployment Pipeline
- `/release-validation`: Release Signature & UKI Evidence Validation

### 2.5 Examinations & Candidate Management
- `/college/exams`: Examination Directory & Scheduling Hub
- `/college/exams/new`: New Examination Registration
- `/college/exams/:id`: Examination Detail & Policy Configuration
- `/college/exams/:id/candidates`: Roster & Candidate URL Assignment
- `/college/candidates`: Candidate Master Database & CSV Import

### 2.6 Student / Candidate Portal
- `/student/home`: Candidate Active Briefing & Schedule
- `/student/exams`: Assigned External Examinations
- `/student/exams/:id`: Pre-Exam Briefing & System Check
- `/student/exams/:id/device-check`: WebRTC Camera, Mic, & Screen Integrity
- `/student/exams/:id/session`: ExamOS Launch & Isolation Handshake
- `/student/history`: Exam History & Verification Receipts

### 2.7 Operator & Invigilator Portal
- `/operator/overview`: Live Center Overview & Terminal Status
- `/operator/exams`: Active Running Exam Sessions
- `/operator/exams/:id/live`: Real-Time Invigilator Monitor Grid
- `/operator/incidents`: Incident Queue & Live Lock Controls

### 2.8 Devices & Hardware Trust
- `/devices`: Registered Device Inventory
- `/devices/enrollment`: Device Hardware Registration & EK Provisioning
- `/devices/compatibility`: Linux Hardware & TPM 2.0 Compatibility Probes
- `/devices/:id/attestation`: Cryptographic TPM Quote & PCR Audit View
- `/usb-inventory`: Verified USB Storage Device Catalogue

### 2.9 Reports & Support
- `/reports`: Consolidated Reporting Hub
- `/reports/exams`: Examination Participation & Status Reports
- `/reports/devices`: Hardware Health & Attestation Reports
- `/reports/security`: Threat Detection & Tamper Reports
- `/support`: Enterprise Support Portal
- `/support/requests`: Ticket & Diagnostic Submission
- `/support/diagnostics`: Live Network & System Diagnostics
- `/support/status`: External Service Status Dashboard
- `/support/recovery`: Appliance Recovery & Emergency Unlock

---

## 3. API Inventory (C Backend)

The backend (`server/main.c`, ports 8080/8443) dispatches to dedicated C controllers:

### 3.1 Authentication & Session Management (`auth_controller.c`)
- `POST /api/v1/admin/login`: Staff authentication (Argon2id/SHA256, MFA challenge)
- `POST /api/v1/admin/logout`: Session termination & token revocation
- `GET /api/v1/admin/session`: Session validation & role reflection
- `POST /api/v1/admin/mfa/setup`: TOTP seed generation & QR code issuance
- `POST /api/v1/admin/mfa/confirm`: TOTP validation & activation
- `POST /api/v1/candidate/login`: Candidate desk authentication with PIN / token
- `POST /api/v1/candidate/logout`: Candidate session end
- `GET /api/v1/candidate/checkin/status`: Desk check-in polling & approval status
- `POST /api/v1/examinations/:id/candidate-tokens`: Issue one-time candidate desk token
- `POST /api/v1/examinations/:id/candidate-checkins`: Candidate check-in queue submission

### 3.2 Institution Accreditation & Multi-Tenant Management (`institution_controller.c`)
- `POST /api/v1/institutions/apply`: Public institution application submission
- `GET /api/v1/admin/institution-applications`: Application queue for platform review
- `POST /api/v1/admin/institution-applications/:id/review`: Approve/reject institution
- `GET /api/v1/admin/institutions`: Enumerate tenant institutions (scoped)
- `POST /api/v1/admin/institutions`: Create tenant institution
- `GET /api/v1/admin/institutions/:id`: Retrieve institution profile
- `POST /api/v1/admin/campuses`: Create campus
- `GET /api/v1/admin/campuses`: List campuses
- `POST /api/v1/admin/rooms`: Create exam room/lab
- `GET /api/v1/admin/rooms`: List rooms

### 3.3 Candidate & Registration Management (`candidate_controller.c`, `registration_controller.c`, `student_controller.c`)
- `GET /api/v1/admin/roster`: Retrieve candidate roster for an examination
- `POST /api/v1/registrations`: Register candidate for an examination
- `POST /api/v1/registration-imports`: Bulk CSV candidate registration import
- `GET /api/v1/examinations/:id/registrations`: Roster list with eligibility status
- `POST /api/v1/examinations/:id/rules`: Configure eligibility rules (attendance, holds)
- `POST /api/v1/examinations/:id/roster/publish`: Versioned roster publication

### 3.4 Examination & Assignment Management (`exam_controller.c`)
- `POST /api/v1/platform/exams/create`: Create examination draft with external URL
- `POST /api/v1/platform/exams/:id/schedule`: Schedule examination start/end/timezone
- `GET /api/v1/platform/exams`: Enumerate examinations
- `POST /api/v1/platform/exams/:id/assignments`: Assign candidate to examination URL
- `DELETE /api/v1/platform/exams/:id/assignments/:cand_id`: Revoke candidate assignment

### 3.5 Device Trust, Attestation & Launch Gate (`device_trust_controller.c`, `tpm_controller.c`)
- `POST /api/v1/devices`: Enroll physical/virtual device with EK/AK
- `GET /api/v1/devices`: List registered devices
- `POST /api/v1/attestation/challenge`: Generate nonced challenge for TPM quote
- `POST /api/v1/attestation/verify`: Verify TPM quote against PCRs 0, 2, 4, 7, 11
- `POST /api/v1/exam-launch/authorize`: **Master Launch Authorization Gate**
  - Validates operator session & tenant boundary
  - Evaluates TPM attestation and device trust
  - Verifies candidate registration & eligibility
  - Validates external exam HTTPS URL against host allowlist
  - Issues CSPRNG one-time launch token and returns authorized exam URL

### 3.6 Session Lifecycle & Proctoring (`exam_session_controller.c`, `session_controller.c`)
- `POST /api/v1/exam-sessions`: Initialize managed exam session
- `POST /api/v1/exam-sessions/:id/start`: Signal external URL launched in kiosk
- `POST /api/v1/exam-sessions/:id/heartbeat`: Periodic kiosk telemetry & focus status
- `POST /api/v1/exam-sessions/:id/submit`: Record session completion receipt
- `POST /api/v1/exam/command`: Real-time emergency lock/unlock command dispatch

### 3.7 Governance, Approvals & Audit (`approvals_controller.c`, `audit.c`)
- `GET /api/v1/approvals`: List pending multi-party approval requests
- `POST /api/v1/approvals/:id/decide`: Approve/reject governance requests
- `POST /api/v1/audit/batch`: Cryptographically record tamper-evident audit events
- `GET /api/v1/ledger`: Stream SHA-256 chained audit ledger

### 3.8 Reporting & Support (`reports_controller.c`, `support_controller.c`)
- `GET /api/v1/reports/exams`: Aggregate examination and candidate metrics
- `GET /api/v1/reports/devices`: Hardware trust and attestation summaries
- `GET /api/v1/reports/security`: Incident and policy breach summaries
- `POST /api/v1/support/tickets`: Create enterprise support ticket
- `GET /api/v1/support/diagnostics`: Run environment diagnostic health checks

---

## 4. Database Inventory (PostgreSQL Schema)

Authoritative persistence managed across 39 SQL migrations (`server/migrations/`):

1. **Authentication & Multi-Tenant Core**:
   - `tenants`, `admin_users`, `admin_user_roles`, `admin_sessions`, `admin_mfa_credentials`, `admin_login_attempts`.
2. **Campus & Department Infrastructure** (Migration 018):
   - `campuses`, `departments`, `rooms`, `staff_members`, `campus_user_assignments`, `department_user_assignments`, `device_assignments`.
3. **Examination Master** (Migration 003, 019):
   - `examinations`: Stores `id`, `institution_id`, `title`, `exam_url`, `allowed_origins`, `status`, `start_time`, `end_time`, `timezone`, `duration_minutes`.
   - `exam_os_policies`: ExamOS security configuration (TPM required, Secure Boot required, USB blocked).
   - `exam_approvals`: Multi-party sign-off records.
   - `exam_status_history`: Audit trail of state transitions (`draft` → `scheduled` → `in_progress` → `closed`).
4. **Candidate & Student Master** (Migration 020, 024):
   - `students`: Roll number, name, email, department, academic status, attendance percentage, administrative holds.
   - `candidates`: Exam desk seating, PIN hash, identity status.
   - `exam_registrations`: Student registration, validation status, approval records.
   - `eligibility_rules`: Configurable validation rules.
   - `exam_student_assignments`: Maps candidate to examination, assigned room, seat, and device.
5. **Device Trust & TPM Attestation** (Migration 004, 022):
   - `devices`: UUID, hardware fingerprint, EK public key, AK public key, enrolled state.
   - `device_trust_policies`: Required TPM version, Secure Boot enforcement, allowed PCR hashes.
   - `attestation_events`: Challenge nonces, quote signatures, PCR digests, verification outcome (`passed` / `failed`).
6. **Candidate Authentication & Launch Gate** (Migration 028, 035):
   - `candidate_exam_auth_tokens`: One-time desk tokens.
   - `candidate_exam_checkins`: Invigilator check-in workflow.
   - `exam_sessions`: Tracks active runtime session, device binding, candidate identity, external exam URL launched, start time, heartbeat, and finish time.
   - `candidate_exam_submissions`: Cryptographic completion receipt with SHA-256 answer/session hash.
7. **Centralized Approval Governance** (Migration 031, 039):
   - `approval_requests`: Action category (`EXAM_POLICY_CHANGE`, `DEVICE_REVOCATION`, etc.), payload, approval status, two-person rule enforcement.
8. **Tamper-Evident Ledger & Audit Catalogue** (Migration 015, 027):
   - `audit_events`: Event category, actor ID, action, resource ID, client IP, payload hash, chained previous hash.

---

## 5. Duplicate Implementation & Scope Cleanliness

1. **Internal Question Engine Cleanup**:
   - `016_exam_questions.sql` and `server/admin/exam_questions.c` contain legacy tables for question storage.
   - **Remediation**: Section 1 mandates that SPPIO must not act as an examination management system. In Phase 4, the external URL launch flow (`/api/v1/exam-launch/authorize`) is authoritative; internal question APIs remain disabled/unreachable in standard candidate production flows.
2. **`candidates` vs `students` Cohesion**:
   - Migration 020 created `students` (academic entity) while Migration 003/028 created `candidates` (desk entity).
   - Both are linked via `student_id` in `exam_student_assignments`. The unified launch flow properly checks both the academic eligibility in `students` and the desk authorization in `candidates` / `exam_student_assignments`.

---

## 6. Security Findings & Protections Verified

1. **SSRF & URL Hijacking Protection (`enterprise_platform.c` & `config_manager.c`)**:
   - Only approved HTTPS schemes are permitted (loopback HTTP permitted only in strictly configured dev mode with port match).
   - User credentials in URLs (`user:pass@host`) are strictly rejected.
   - Path traversal tokens (`..`) and control characters are rejected.
   - External domains are validated against `EXAMOS_ALLOWED_EXAM_HOSTS` allowlist.
2. **One-Time Launch Token Security**:
   - Generated with OpenSSL CSPRNG (`RAND_bytes(32)`).
   - Stored in hashed form; invalidated upon launch or expiry.
   - Tied to authenticated candidate and enrolled device.
3. **Appliance Isolation**:
   - ExamOS kiosk runs with Wayland/Cage, Chromium in `--kiosk --app=URL` mode, clipboard disabled, DevTools disabled, local file access blocked, and Crashpad telemetry monitored.

---

## 7. Missing Functionality & Phase 4 Action Plan

To achieve 100% compliance with Section 5.1 and Section 24 of the Phase 4 specification:
1. **Migration 040 (`040_candidate_exam_url_assignments.sql`)**:
   - Extend `exam_student_assignments` with dedicated fields for candidate-specific URL overrides (`assigned_exam_url`), `exam_date`, `start_time`, `end_time`, `timezone`, `assignment_status`, `credential_ref`, `created_by`, `approved_by`, and revocation tracking (`revoked_at`, `revoked_by`, `revocation_reason`).
   - Create `candidate_exam_assignment_audit` table to log all URL assignment modifications and revocations.
2. **Backend Controller Extension (`candidate_controller.c` / `exam_controller.c`)**:
   - Support assigning individual external exam URLs per candidate with strict HTTPS validation.
   - Update `/api/v1/exam-launch/authorize` to prioritize the candidate's individual assigned URL over the general exam URL.
3. **Comprehensive End-to-End Acceptance Test Script (`./scripts/e2e/full-acceptance.sh`)**:
   - Complete 12-stage sequential test from Institution Onboarding → Candidate Registration → Individual URL Assignment → Secure Credentials → swtpm/QEMU boot → Candidate Auth → Launch Gate → Session Monitoring → Completion Verification → Audit Reporting.
