# ExamOS implementation inventory

**Snapshot:** 2026-10-12
**Repository state:** development prototype; this inventory is a source and
evidence baseline, not a release certification.

## Classification

- **Implemented and validated** means validation is recorded for the stated
  scope only; it is not a production or hardware claim.
- **Implemented but not validated** means source exists without sufficient
  current evidence.
- **Partially implemented** means source or static configuration exists, but a
  required integration, policy, or validation link is absent.
- **Blocked** requires an external authority, approved dependency, operational
  input, or physical-device validation.

## Current inventory

| Component | Existing state | Required change | Dependencies | Validation | Classification |
| --- | --- | --- | --- | --- | --- |
| Native appliance services | Kiosk, agent, server (C) and proctoring (C++17) are built by the top-level native Make targets. | Preserve compiler hardening and validate each release build from a clean source snapshot. | GCC/G++, OpenSSL, libcurl, Linux runtime packages. | Historical build evidence is mixed/dirty-tree. | Implemented but not validated |
| P0 image and virtual boot | mkosi builds a Debian image with a native C++ serial first-boot account setup, the Debian console-login package, and an OVMF boot path. | Rebuild and bind ISO evidence from a clean source snapshot; validate physical firmware and production provisioning separately. | Controlled clean build, approved provisioning and target-device validation. | Fresh dirty-tree image build, QEMU/OVMF serial startup, first-boot account/password creation and non-root serial login pass with TCG; this is development evidence only. | Partially implemented |
| P1 kiosk and network | Static kiosk and network configuration plus tests exist. | Resolve failing artifact/guest boot checks and validate a booted kiosk flow. | Exam URL and supported guest/device environment. | P1 result is recorded FAIL/BLOCKED. | Partially implemented |
| P2 runtime lockdown | nftables, AppArmor, USBGuard, dm-verity and kernel-policy configuration exist. | Execute positive and negative runtime tests on isolated images, then approved hardware. | Build artifacts, deployment configuration, VM/device plan. | Mandatory P2 tests are recorded NOT_RUN. | Implemented but not validated |
| P3 native attestation | C server has TPM quote parsing, OpenSSL signature/X.509 verification, and production registry checks. | Complete production enrollment, genuine event-log binding, and hardware evidence. | Approved registry, EK/AK enrollment, real TPM and revocation policy. | Development swtpm evidence is not release evidence. | Partially implemented |
| P3 Go verifier | A development-only standalone verifier exists. | Keep development-only; it must not authorize key release. | None for its current isolated role. | Issue register records a fail-closed defect under remediation. | Implemented but not validated |
| Release-provenance foundation | Six preserved Python schema/tool/test/documentation files form a fail-closed development prototype. | Keep isolated; no production integration. | None for current BLOCKED behavior. | Its `verify_release()` intentionally cannot return `VERIFIED`. | Implemented and validated |
| Native release verifier | No native implementation or approved C++ JSON/JCS stack exists. | Approve parser, RFC 8785 JCS implementation, test framework, supply-chain controls, then implement independently. | External dependency approval; trust authority; revocation policy. | No native verifier tests exist. | Blocked |
| Secure Boot / UKI | Development UKI construction exists. | Bind an approved DB certificate, sign release UKI externally, and validate positive/negative boot-chain behavior. | Production signing authority, key custody, approved certificate. | Current production evidence is absent. | Blocked |
| dm-verity | Configuration and test scaffolding exist. | Bind root hash into trusted boot chain and test corruption rejection. | Release image artifacts and approved boot policy. | Runtime enforcement is not evidenced. | Implemented but not validated |
| P4 proctoring | Native C++ capture/event-chain code and optional OpenCV code exist. | Package approved pinned models and conduct governed evaluation. | Licensed models, consented labelled data, OpenCV packaging. | Existing quality claim is invalidated. | Blocked |
| P5 candidate behavior and review | P5-A through P5-E have recorded tests. | Supply provider, privacy/review controls, and fresh P0-P4 inputs. | Approved provider and governance decisions. | P5-F through P5-I remain blocked. | Partially implemented |
| P6 release readiness | Prerequisite audit and release-readiness documentation exist. | Complete trust custody, hardware matrix, red-team, pilot, and independent approval. | Organizational and physical-validation inputs. | P6 is recorded BLOCKED. | Blocked |

## Protected implementation boundaries

The following remain unchanged until a separately approved integration phase:

- `tests/p3/release-gate.py`
- `tests/production/collect-boot-chain-evidence.sh`
- `.github/workflows/production-release.yml`
- existing ISO, raw-image, artifact, recovery-evidence, firmware, TPM, and
  Secure Boot state

## Immediate implementation order

1. Obtain an approved native strict-JSON and RFC 8785 JCS dependency decision.
2. Define authenticated trust-authority and revocation inputs.
3. Implement and independently review the isolated native verifier.
4. Propose, rather than perform, a separate gate-integration change.

Until steps 1 and 2 are complete, production release verification remains
**BLOCKED**. Repository-level verification must never be reported as proof of
firmware enforcement, physical TPM validation, or production release approval.
