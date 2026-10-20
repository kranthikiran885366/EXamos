# P0 Production Completion Register

**Status:** BLOCKED. This register separates repository implementation from
acceptance evidence and external prerequisites. A source-only check cannot
promote P0 to production.

## Engineering work in the repository

| ID | Work | Current state | Completion evidence |
|---|---|---|---|
| ENG-01 | Keep partition type requirements in one canonical configuration consumed by ISO build and image forensics | Strict parser is shared; ISO and forensic checks consume the canonical GUIDs. Runtime image validation pending. | Parser positive/negative tests and successful full P0 gate |
| ENG-02 | Reconcile duplicate P0 checks and output schemas across orchestrator, enterprise validator, and forensic analyzer | Image size/partition checks now have one forensic owner; orchestrator binds and validates that report. Remaining check contracts need full-run validation. | One owner per check; schema validation; full gate |
| ENG-03 | Pin CI runner image, OS packages, mkosi/QEMU/OVMF/toolchain and package repository inputs | Implemented in-tree | `image/p0/sources.lock`, `image/p0/toolchain.lock`, mkosi `Mirror=`, `ubuntu-24.04` in `.github/workflows/p0.yml`; `tests/p0/pin-check.sh` |
| ENG-04 | Add two clean builds from the same pinned inputs and compare declared reproducible outputs | Harness added; image evidence open | `tests/p0/reproducible-build.sh` with `EXAMOS_P0_REPRO_MODE=image`; native mode cannot close ENG-04 |
| ENG-05 | Generate and bind SBOM, dependency provenance, source tree digest, build config and artifact digests | Open | Signed/attested provenance bundle verified by CI |
| ENG-06 | Make every release value a validated configuration or explicit standard/target constant; remove secrets, user/device-specific defaults and environment-specific paths | Agent deployment endpoint/device identity and release inputs no longer fall back to baked-in values; no default admin password is generated. Full repository audit remains open. | Repository scan plus positive/negative configuration tests |
| ENG-07 | Ensure every P0 result has one versioned schema, source commit/tree state, command, tool versions, artifact digests and PASS/FAIL/BLOCKED/NOT_RUN | Aggregate result schema is validated; forensic output is versioned and artifact-bound. Uniform metadata across every phase remains open. | Schema validation and clean full-gate evidence |
| ENG-08 | Reconcile historic conflicting ISO boot results without editing historical evidence | Open | Fresh run supersedes old evidence with exact artifact binding |
| ENG-09 | Confirm enterprise gate consumes the current forensic output and does not repeat its checks with weaker logic | Duplicate size/partition checks removed; full validation pending | Full enterprise run with consistent check inventory |
| ENG-10 | Remove fabricated agent identity, TPM measurements, quote signatures, and default administrator credentials | Agent requires provisioned identity and fails closed when hardware attestation cannot be established; fabricated TPM values and the known development admin password were removed. End-to-end TPM quote implementation remains blocked pending key provisioning and verifier integration. | Native agent build, negative configuration tests, physical TPM challenge and server verification |

## Work performed in the current source pass

- P0 image builds now invoke `image/p0/mkosi.conf` explicitly with fresh isolated output, cache, and build directories; the build fails if mkosi fails or does not emit exactly one disk image.
- Forensics binds to the image and checksum from the current isolated run, uses the canonical partition GUIDs, rejects label-based guesses and checksum mismatches, and reports failure for any mandatory forensic check failure.
- Enterprise validation consumes that current-run forensic report. Critical `WARN` and `BLOCKED` domains fail the gate. Repository structure checks no longer create missing directories and hide the defect.
- P0 package-pin parsing accepts CRLF input without treating carriage returns as part of pinned values.
- Agent and local-launcher changes remove the known default admin password, require deployment-provided server/device/token values, require HTTPS, and fail closed when TPM/event-log evidence is absent. The current agent still cannot produce a cryptographic TPM quote; this is an explicit implementation blocker, not a pass.
- Linux checks run in WSL for the source state, pin parser, deployment configuration, repository integrity, ignored-key policy, and result schema. The native agent compiles. No full P0 image/boot gate, two-build reproducibility result, VMware ISO boot, physical-device test, production trust ceremony, or independent acceptance was produced by this pass.

## Evidence or inputs that must be supplied outside source edits

| ID | Blocker | What you need to arrange | Evidence to add |
|---|---|---|---|
| EXT-01 | Current checkout is dirty and has extensive uncommitted/untracked changes | Review and commit the intended source; preserve unrelated work; run from a clean commit | `tests/production/clean-source-gate.sh`; commit ID and clean tree manifest |
| EXT-02 | Clean reproducibility has not been demonstrated | Provide pinned package snapshot/network mirror and capacity for two isolated builds | `tests/p0/reproducible-build.sh` image mode; two build manifests and digest comparison |
| EXT-03 | VMware Workstation ISO boot is not evidenced | Provide VMware Workstation host/VM access and run the exact built ISO with UEFI | `tests/p0/vmware-optical-boot.sh`; version, VMX, ISO digest, guest log. No host EFI/TPM/Windows writes |
| EXT-04 | Physical device support is not qualified | Declare exact supported models/revisions and arrange safe test devices, recovery media, and test time | In-scope candidate: Dell Vostro 15 3510 (**NOT QUALIFIED**). See `docs/production/hardware-qualification.md` |
| EXT-05 | Production Secure Boot/release trust has not been provisioned | Organization security owner supplies approved signing identity, custody process, trust enrollment and release registry | `docs/production/signing-ceremony.md` and `tests/production/trust-provisioning-gate.sh` |
| EXT-06 | Physical TPM enrollment/challenge is unproven | Device identity/PKI owner supplies enrollment service and physical TPM test devices | `tests/production/server-verified-tpm-challenge.sh`; no swtpm fallback |
| EXT-07 | Independent production acceptance is outside P0 scripts | Security/operations owners define risk acceptance, incident/update/support process and independent assessment | `docs/production/independent-assessment.md` and `tests/production/external-acceptance-gate.sh` |

## Definition of done

P0 source implementation is complete only when all ENG items are closed and
the clean CI gate passes. P0 release qualification additionally requires the
applicable EXT evidence. Missing hardware or trust evidence remains BLOCKED;
it is not replaced with simulator results. Standards-defined identifiers and
the declared target architecture may remain explicit constants, but they must
be centralized and documented. Credentials, personal/device values, and
builder-local paths must be provisioned or discovered at runtime.
