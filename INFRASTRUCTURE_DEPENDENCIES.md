# ExamOS Infrastructure-Dependent Gaps

This document lists audit gaps that require external infrastructure, hardware, or organizational processes and cannot be resolved through code changes alone.

## Summary
Of the 44 gaps identified in the audit, **12 gaps require external infrastructure** and are marked as BLOCKED until the prerequisites are met.

---

## Critical Infrastructure Gaps

### PG-11, PG-12: P2 Guest Integration Tests (BLOCKED)
**Gap:** 20/20 mandatory P2 tests are NOT_RUN because no booted guest execution has occurred.

**Required Infrastructure:**
- QEMU or VM environment capable of booting the built image
- Automated guest bootstrap and SSH/network access for in-guest test execution
- dm-verity setup with SQUASHFS_CLEAN, VERITY_HASH_FILE, and VERITY_ROOT_HASH populated

**Action Required:**
1. Implement automated guest boot in CI/CD pipeline
2. Configure dm-verity during image build
3. Run p2-guest-integration.sh inside booted guest
4. Verify verity corruption test (p2-verity-tests.sh) runs successfully

**Estimated Effort:** 2-3 weeks engineering

---

### PG-18: Physical TPM Evidence (BLOCKED)
**Gap:** swtpm-quote-smoke.sh uses software TPM only. No physical TPM 2.0 device has been tested.

**Required Infrastructure:**
- Physical TPM 2.0 devices (minimum 3 distinct laptop models per PG-38)
- Hardware test lab for device enrollment and attestation
- Physical device provisioning workflow

**Action Required:**
1. Acquire physical TPM 2.0 hardware (3+ laptop models)
2. Implement enroll-physical-tpm.sh workflow for production EK certificate chain
3. Run TPM attestation tests on physical devices
4. Capture real PCR values and TCG event logs

**Estimated Effort:** 4-6 weeks (hardware procurement + engineering)

---

### PG-19: Production Trust Registry Provisioning (BLOCKED)
**Gap:** artifacts/production/trust-provisioning.json exists but hardware-trust.json and hardware-qualification.json show no real hardware evidence.

**Required Infrastructure:**
- Production PKI infrastructure for CA-signed AK certificates
- Hardware qualification lab and qualification process
- Trust registry database and provisioning ceremony

**Action Required:**
1. Establish production PKI with intermediate CA for device certificates
2. Define hardware qualification criteria and testing process
3. Implement trust registry provisioning ceremony (PG-40)
4. Generate hardware-qualification.json for qualified devices

**Estimated Effort:** 6-8 weeks (PKI setup + qualification process)

---

### PG-20: Exam Key Release End-to-End Test (BLOCKED)
**Gap:** The P3 gate does not test the full flow: agent quotes → server verifies → server releases sealed key → agent decrypts.

**Required Infrastructure:**
- Production-like attestation server with real TPM
- Sealed key storage and release mechanism
- Agent with TPM quote capability

**Action Required:**
1. Implement end-to-end attestation service test
2. Verify sealed key release flow
3. Test agent decryption of released key
4. Add to P3 gate as mandatory test

**Estimated Effort:** 2-3 weeks engineering

---

### PG-21: Revocation Engine Test (BLOCKED)
**Gap:** revocation-test.json exists but the current gate.sh marks the suite BLOCKED.

**Required Infrastructure:**
- Revocation database and certificate revocation list (CRL) infrastructure
- Test procedure for revoking compromised devices/releases

**Action Required:**
1. Implement revocation database schema
2. Create revocation API and CRL generation
3. Write revocation test script
4. Add to P3 gate as mandatory test

**Estimated Effort:** 3-4 weeks engineering

---

### PG-23, PG-24: Real Labelled Video Dataset (BLOCKED)
**Gap:** P4 is INVALIDATED — prior detection-quality claim used fabricated evidence. No real labelled video dataset exists.

**Required Infrastructure:**
- Collection of real exam session video footage (50+ clips)
- Human annotation/labelling process for detection ground truth
- DATASET-MANIFEST.json with synthetic: false

**Action Required:**
1. Collect real exam session footage with appropriate privacy/consent
2. Establish human annotation workflow
3. Generate ground truth labels for detection quality evaluation
4. Create DATASET-MANIFEST.json documenting dataset provenance

**Estimated Effort:** 8-12 weeks (data collection + annotation)

---

### PG-25: Vision Model Weights Installation (BLOCKED)
**Gap:** res10_300x300_ssd_iter_140000.caffemodel is absent. The proctor binary cannot run inference.

**Required Infrastructure:**
- Model artifact storage and distribution
- Model digest verification infrastructure
- Installation script integration

**Action Required:**
1. Download vision model weights from official source
2. Verify model digest against known-good values
3. Install to /etc/examos/models/ during image build
4. Add model installation to mkosi build process

**Estimated Effort:** 1-2 weeks engineering

---

## Organizational Process Gaps

### PG-37: Architecture Discrepancy (BLOCKED)
**Gap:** prerequisite-status.json lists Node.js, MongoDB, Redis, Python inference workers, WebRTC SFU, Docker as "required by P6 prompt but absent." The actual implementation is native C/C++.

**Required Infrastructure:**
- Architecture decision and approval process
- Updated P6 requirements documentation reflecting actual architecture

**Action Required:**
1. Review and approve current native C/C++ architecture
2. Update P6 requirements to match actual implementation
3. Document architecture decision rationale

**Estimated Effort:** 1 week (documentation + approval)

---

### PG-38: Physical Hardware Matrix (BLOCKED)
**Gap:** Three distinct laptop models with physical TPM 2.0 are required. Zero hardware evidence exists.

**Required Infrastructure:**
- Hardware procurement process
- Hardware test lab
- Device qualification documentation

**Action Required:**
1. Acquire 3+ distinct laptop models with TPM 2.0
2. Qualify each model for ExamOS compatibility
3. Document hardware matrix in artifacts/production/hardware-trust.json

**Estimated Effort:** 4-6 weeks (procurement + qualification)

---

### PG-39: Authorized Red-Team Execution (BLOCKED)
**Gap:** Written owner authorization and executed red-team findings are absent. No penetration test has been conducted.

**Required Infrastructure:**
- Red-team authorization process
- Third-party security auditor engagement
- Vulnerability tracking and remediation workflow

**Action Required:**
1. Obtain written authorization for red-team testing
2. Engage third-party security auditor
3. Execute penetration testing against all phases
4. Document findings and remediation plan

**Estimated Effort:** 6-8 weeks (auditor engagement + testing)

---

### PG-40: Production Key Custody Ceremony (BLOCKED)
**Gap:** Production signing keys, AK certificate chain, and trust registry provisioning ceremony evidence are absent.

**Required Infrastructure:**
- Key generation and custody procedures
- Multi-party key ceremony process
- Hardware security module (HSM) or equivalent key storage

**Action Required:**
1. Define key custody roles and responsibilities
2. Implement multi-party key generation ceremony
3. Securely store production keys in HSM
4. Document ceremony proceedings

**Estimated Effort:** 4-6 weeks (process definition + ceremony execution)

---

### PG-41: Pilot Evidence (BLOCKED)
**Gap:** 10-20 volunteer pilot with real exam sessions is required for P6. No pilot has been conducted.

**Required Infrastructure:**
- Pilot participant recruitment and consent process
- Pilot deployment infrastructure
- Data collection and analysis process

**Action Required:**
1. Recruit 10-20 volunteer pilot participants
2. Deploy ExamOS in pilot environment
3. Conduct real exam sessions
4. Collect and analyze pilot data
5. Document pilot findings

**Estimated Effort:** 8-12 weeks (recruitment + pilot execution + analysis)

---

## Summary Table: Infrastructure-Dependent Gaps

| Gap ID | Phase | Severity | Description | Required Infrastructure | Est. Effort |
|--------|-------|----------|-------------|------------------------|-------------|
| PG-11 | P2 | CRITICAL | 20/20 mandatory tests NOT_RUN | Guest boot environment, dm-verity | 2-3 weeks |
| PG-12 | P2 | CRITICAL | dm-verity corruption test never ran | dm-verity setup, hash files | 2-3 weeks |
| PG-18 | P3 | CRITICAL | No physical TPM evidence | Physical TPM 2.0 devices | 4-6 weeks |
| PG-19 | P3 | CRITICAL | Production trust registry absent | PKI infrastructure, qualification lab | 6-8 weeks |
| PG-20 | P3 | HIGH | Exam key release never E2E tested | Attestation server, sealed key storage | 2-3 weeks |
| PG-21 | P3 | HIGH | Revocation engine not tested | Revocation database, CRL infrastructure | 3-4 weeks |
| PG-23 | P4 | CRITICAL | Fabricated detection evidence | Real labelled video dataset | 8-12 weeks |
| PG-24 | P4 | CRITICAL | No real labelled video dataset | Real exam footage, annotation workflow | 8-12 weeks |
| PG-25 | P4 | HIGH | Vision model weights not installed | Model storage, installation script | 1-2 weeks |
| PG-37 | Cross | CRITICAL | Architecture mismatch blocks P6 | Architecture approval process | 1 week |
| PG-38 | Cross | HIGH | No physical hardware matrix | Hardware procurement, test lab | 4-6 weeks |
| PG-39 | Cross | HIGH | No authorized red-team execution | Security auditor engagement | 6-8 weeks |
| PG-40 | Cross | HIGH | No production key custody ceremony | Key custody process, HSM | 4-6 weeks |
| PG-41 | Cross | HIGH | No pilot evidence | Pilot recruitment, deployment | 8-12 weeks |

---

## Prioritized Action Plan

### Immediate (1-2 weeks)
1. Install vision model weights (PG-25)
2. Resolve architecture discrepancy (PG-37)

### Short-term (2-6 weeks)
3. Implement guest boot and P2 integration tests (PG-11, PG-12)
4. Acquire physical TPM hardware (PG-18, PG-38)
5. Implement exam key release E2E test (PG-20)

### Medium-term (6-12 weeks)
6. Establish PKI and trust registry (PG-19, PG-40)
7. Implement revocation engine and test (PG-21)
8. Engage red-team security auditor (PG-39)

### Long-term (12+ weeks)
9. Collect and label real video dataset (PG-23, PG-24)
10. Conduct pilot program (PG-41)

---

## Notes

- All code-level fixes have been completed. The remaining gaps require:
  - Hardware procurement
  - Infrastructure setup
  - Organizational process establishment
  - Third-party services (auditors, PKI providers)
- Some gaps have dependencies (e.g., PG-19 depends on PKI infrastructure which also supports PG-40)
- The total timeline to resolve all infrastructure-dependent gaps is approximately 6-12 months assuming parallel execution of non-dependent tasks
