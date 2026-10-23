# ExamOS release readiness

**Decision: NOT PRODUCTION READY.**

**Date:** 2026-10-22

**Commit:** `ff2f040c3f463ee57062513d8deafe4e845fb546` (DIRTY worktree)

P0, P3, P4, P5 and production certification remain **separate** results. A
swtpm quote PASS is development evidence only. No physical TPM, Secure Boot,
dm-verity, signing-key or provider result is asserted here.

The current implementation-to-evidence mapping is maintained in
[BLOCKER_CLOSURE_REPORT.md](BLOCKER_CLOSURE_REPORT.md). It records which
controls are code/test complete and which still require independently
provisioned signing, consent, and hardware evidence. The transport contract is
in [TLS_PROVISIONING.md](TLS_PROVISIONING.md); the issue history and this
increment's fixes are in [ISSUE_REGISTER.md](ISSUE_REGISTER.md).

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

Legend: PASS = verified by executable evidence in this worktree; FAIL = a
required control failed; BLOCKED = the environment cannot supply the required
input; NOT TESTED = no execution was performed.

| Criterion | Verdict (2026-10-22) |
|-----------|----------------------|
| Full native build | PASS (`make all`, EXIT=0; server, agent, kiosk launcher, proctoring) |
| Server runtime smoke | PASS (21/21 endpoint checks) |
| TLS transport and headers | PASS (9/9: handshake, HSTS, CSP, frame/MIME/referrer, cleartext refusal, TLS 1.2) |
| Binary hardening | PASS (server 6/6, A+) |
| Production placeholder scan | PASS |
| Unresolved critical/high code issues from earlier audits | Code fixes applied; physical/provisioning items remain BLOCKED (see issue register) |
| P0 release gate | BLOCKED (dirty tree; physical evidence absent). Software-toolchain boot: disk image PASS (QEMU/OVMF), ISO full-root boot BLOCKED (optical limitation, see below) |
| P1 kiosk/network static controls | PASS as static checks; gate BLOCKED (dirty tree, external `EXAM_URL`). Disk-image boot contract (OVMF/QEMU) PASS |
| P2 lockdown | BLOCKED (no image/guest/physical hardware; static audit PASS=48 FAIL=0 BLOCKED=0) |
| P3 attestation | BLOCKED (swtpm quote PASS as development evidence; external trust/release assets unavailable) |
| P4.1 detection quality | BLOCKED (no consented labelled clips or approved model artifacts) |
| P4.2 tamper evidence | PASS (T0–T8, 9/9; checkpoint HMAC verified independently) |
| P4.3 event concurrency | PASS (500/500 events, 50 sessions, zero gaps, zero verifier failures) |
| P4.4 browser media restriction | BLOCKED (no external `EXAM_URL`) |
| P4.5 P0–P3 regression | BLOCKED (P3 gate BLOCKED) |
| P5.1 behaviour engine | PASS (6/6) |
| P5.2 variant engine | PASS (6/6) |
| P5.3 viva engine | BLOCKED (no server-held submitted exam; no LLM provider) |
| Real TPM quote signature verification | PASS in C server vs swtpm; NOT TESTED on hardware |
| Secure Boot + signed UKI | NOT TESTED as enforcement |
| dm-verity enforcement | NOT TESTED live |
| Physical external boot / hardware-backed attestation | NOT TESTED |
| Production certificate/signing/provider provisioning | BLOCKED (operator inputs not present) |

## Code-complete controls in this increment

- In-process TLS 1.2+ with approved ciphers, HSTS and security headers; a
  cleartext non-loopback listener is refused before `bind()`. Certificate and
  key provisioning is documented and remains an operator input.
- Ledger blocks are HMAC-authenticated and reject forged or truncated chains.
  Exam submission is published only after the durable ledger append succeeds;
  answer mutation is atomic with the submission check and duplicate
  submissions are rejected.
- The event chain accepts 64-hex candidate tokens without truncation; every
  event path uses the same session identifier capacity. Viva persistence uses
  the same 128-byte session capacity and does not expose the session token as a
  reviewer question reference.
- Checkpoints are HMAC-signed and independently verifiable with
  `tools/exam-event-verify --checkpoint`; a tampered signature is rejected.
- P5 behaviour, variant, viva and reviewer routes are implemented. Viva
  identity is token-derived and question/answer context is read only from the
  server-held, receipt-bound submission.
- No examination identity is fabricated at runtime. The behaviour/score and
  exam/variant routes resolve a provisioned `EXAM_ID` from exam.conf and fail
  closed with `EXAM_IDENTITY_NOT_PROVISIONED` when it is absent; the hardcoded
  `EXAM-MAIN` default was removed. Variant seeds, watermarks and risk scores
  are now bound to a real, provisioned examination identity.
- Dead scaffolding and fabricated detector paths were removed rather than left
  as callable APIs.
- Test-fixture defects that masked failures were corrected: the binary-canary
  check no longer races `readelf` under `pipefail`, P2 maps an unavailable image
  to BLOCKED instead of FAIL, and P4/P5 fixtures provide the mandatory event
  provenance and isolated stores.

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

The result remains **development-only**: the source tree is dirty; Secure
Boot, TPM/measurement, and dm-verity enforcement are not certified; no
physical model/device is production-qualified. Current P0 hardware support is
limited to a Debian Trixie x86-64 UEFI guest image and virtual acceptance;
consult the P0 platform boundary in `docs/development/p0-requirements.md`.

## Software-toolchain boot validation (2026-10-23)

Before any physical hardware testing, the refreshed boot image was validated
under QEMU q35 + OVMF (`OVMF_CODE_4M.fd`) + KVM, with `swtpm` (software
TPM 2.0). Evidence under `artifacts/software-toolchain/`:

- **Disk image (`output/examos.raw` / `output/examos.vmdk`) — PASS.** Full
  chain: OVMF -> systemd-boot -> UKI (`EFI/Linux/examos-6.12.111+…efi`, sections
  `.linux`/`.initrd`/`.ucode`, no `root=`, gpt-auto-generator root type GUID
  `4F68BCE3`) -> initrd -> `/dev/gpt-auto-root` -> `Welcome to ExamOS 0.3.0`
  -> `graphical.target` queued, no emergency. SHA256
  `4b366df63f999c9054ac5072de12ca9642b1acb762729b4a861f996f6a34c185`.
  Root partition `/usr/local/bin` binaries refreshed (post-fix builds) and
  SHA-verified in-image.
- **TPM fail-closed — confirmed (correct behaviour, not a defect).** With the
  unprovisioned software TPM attached (`tpm-tis`), `systemd-pcrfs@sysroot`
  fails -> `sysroot.mount` dependency fails -> initrd refuses switch-root ->
  emergency. A blank TPM must not yield a bootable root. Production images
  provision sealing keys via the deployment authority.
- **ISO (`output/examos.iso`) — full-root boot BLOCKED (architectural
  limitation).** Boot reaches the full chain (OVMF -> systemd-boot -> UKI ->
  kernel -> systemd initrd) but `initrd-switch-root` fails because
  `gpt-auto-generator` does not scan optical media for the root partition;
  the El Torito EFI FAT (LBA 34) is also not partition-aligned, so disk-mode
  presentation has no bootable ESP. The **VMDK/disk image is the fully-bootable
  VMware artifact**; the ISO is for optical-chain/USB-disk imaging only. See
  `output/VMWARE_DEPLOYMENT.md`.

## Remaining approvals

1. User approval to write a **named external** USB/SSD only (Phase C).
2. Independent production registry signing ceremony.
3. Physical PCR baseline approval for this laptop (not auto-enroll).
4. Provision production TLS certificate/key and record the chain of custody.
5. Provision an approved exam content package, durable submission storage and
   an LLM provider before re-running the P5 viva gate.
