# ExamOS release readiness

**Decision: NOT PRODUCTION READY.**  
**Date:** 2026-10-12
**Commit:** `c8d8c6149458e9c1611966d5f2db66ed2f42e2d1` (DIRTY worktree)

P0, P3, and production certification remain **separate** results. An 18/18 swtpm suite PASS is development evidence only.

The current implementation-to-evidence mapping is maintained in
[BLOCKER_CLOSURE_REPORT.md](BLOCKER_CLOSURE_REPORT.md). It records which
controls are code/test complete and which still require independently
provisioned signing, consent, and hardware evidence.

The link-by-link boot authorization state is maintained separately in
[BOOT_CHAIN_CLOSURE_REPORT.md](BOOT_CHAIN_CLOSURE_REPORT.md). All links are
currently BLOCKED; physical testing is not authorized.

> **Evidence reconciliation:** `artifacts/p3/results.json` marks the aggregate
> P3 result **INVALIDATED** because it came from a dirty tree and a subsequent
> run aborted at P3-014. The separate 18/18
> `attestation-suite-results.json` is not an aggregate P3 pass or release
> evidence. See the current
> [end-to-end audit](END_TO_END_AUDIT.md).

## Gate table

| Criterion | Verdict |
|-----------|---------|
| No unresolved critical/high issues | FAIL (E-01–E-12, A-01–A-14) |
| Authenticated fail-closed production config | FAIL until HMAC/session/registry/EK proven in production mode |
| Real TPM quote signature verification | PASS in C server vs swtpm; NOT TESTED on hardware |
| Secure device/release registry | Development unsigned JSON; production signing not provisioned |
| Nonce/replay | PASS in suite (software TPM) |
| Ledger integrity + session persistence | Oct 11 failure is historical; current P0 smoke/runtime evidence must be regenerated and does not certify production key provisioning |
| Exam-key adversarial denial | PASS in suite cases; not hardware |
| Secure Boot + signed UKI | NOT TESTED as enforcement |
| dm-verity enforcement | NOT TESTED live |
| Reproducible build + manifest | FAIL (dirty tree; P0 provenance issues) |
| VM boot + negative paths | VM boot exists; negative SB/verity NOT TESTED |
| Physical external boot | NOT TESTED |
| Hardware-backed attestation | NOT TESTED |
| Evidence hashes | Oct 11 package hashes recorded; do not overwrite |

## P0 validation update (2026-10-12; artifact reconciliation)

QEMU KVM initialization succeeded on WSL2. A recorded disk boot and
snapshot-isolated first-boot account/login passed for image digest
`a531ad41eeb3a1cb8a01a714a7c0af625acd3aca4264ad43be30f26a1361de3f`, but
the current disk build has digest
`c0b4619a7e1f3fb72cff284c493dd8988074bc61113926d29fead480997b00af`.
The current ISO digest
`64fe70b0cce8c68834de0c6a73e9dbeb0f1e2fa3b09a22f5b231c791aba1eae7`
failed its QEMU UEFI optical boot (exit 139). The prior PASS records do not
validate the current disk.

The result remains **development-only**: the source tree is dirty; optical
ISO boot and VMware boot have not passed; Secure Boot, TPM/measurement, and
dm-verity enforcement are not certified; no physical model/device is
production-qualified. Current P0 hardware support is limited to a Debian
Trixie x86-64 UEFI guest image and virtual acceptance; consult the P0 platform
boundary in `docs/development/p0-requirements.md`.

## Remaining approvals

1. User approval to write a **named external** USB/SSD only (Phase C).
2. Independent production registry signing ceremony.
3. Physical PCR baseline approval for this laptop (not auto-enroll).
