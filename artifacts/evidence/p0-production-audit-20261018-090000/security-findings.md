# ExamOS P0 — Security Findings & Risk Assessment

**Audit Run ID:** `p0-production-audit-20261018-090000`  
**Classification:** Development Prototype Security Audit

---

## 1. Confirmed Security Findings

### Finding SEC-P0-01 (Severity: MEDIUM) — Dirty Source Tree Invalidates Release Provenance
- **Evidence:** `git status --short` reports uncommitted modifications and untracked files.
- **Impact:** Any binary or image built from a dirty working tree lacks an immutable cryptographic link to a git commit SHA. Cannot be certified for production release.
- **Remediation:** Commit or clean all changes in a dedicated release worktree prior to production builds.

### Finding SEC-P0-02 (Severity: HIGH) — Host Memory Edge in Default WSL2 Configuration
- **Evidence:** Default WSL2 memory assignment allocates 4,010,212 KiB (~3916 MiB), which falls 86 MiB below the documented 4,194,304 KiB threshold unless `.wslconfig` is tuned to `>= 5GB`.
- **Impact:** Host check fails in default out-of-the-box WSL2 installations.
- **Remediation:** Documented requirement in `p0-requirements.md` requires `.wslconfig` setting `memory=5GB`.

### Finding SEC-P0-03 (Severity: LOW) — Development First-Boot Console Credentials Volatility
- **Evidence:** `first-boot-test.cpp` creates a temporary local operator account during initial boot.
- **Impact:** In development images, interactive account creation is permitted. In production images, all interactive local console account creation must be disabled in favor of TPM-sealed credentials.
- **Remediation:** Enforce `03-p2-lockdown.sh` account lockouts in production builds.

### Finding SEC-P0-04 (Severity: CRITICAL / BLOCKER) — Absence of Production Hardware Attestation
- **Evidence:** All TPM interactions are software-simulated (`swtpm`). Physical TPM quote generation and signature verification against enrolled EK/AK certificates are not yet implemented.
- **Impact:** Device identity cannot be proven on physical hardware.
- **Remediation:** Phase 3 implementation queue item.
