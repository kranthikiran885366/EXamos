# Boot-chain closure report

**Status:** BLOCKED — this is an evidence map, not a release certificate.  
**Snapshot:** 2026-10-11.  
**Known source revision for the isolated P0 evidence:**
`c8d8c6149458e9c1611966d5f2db66ed2f42e2d1`, with a dirty tree (346 paths).

The intended authorization chain is:

```text
kernel command line -> UKI contents -> UKI signature -> Secure Boot
-> measured boot -> dm-verity root hash -> TPM quote -> event-log replay
-> production authorization
```

Each arrow has to be proven for the *same release identity*. A successful
lower link never proves an absent higher link.

| Link | Artifact / expected verifier | Current evidence | Status | Failure modes still requiring closure |
|---|---|---|---|---|
| Kernel command line | Release [`image/mkosi.conf`](../../image/mkosi.conf); extract `.cmdline` from generated UKI with `objcopy` | Release source declares `lockdown=confidentiality`, module signature enforcement and IOMMU hardening. The isolated P0 UKI was generated from [`image/p0/mkosi.conf`](../../image/p0/mkosi.conf), whose command line is development `multi-user.target` and lacks release lockdown. | BLOCKED | Build the release profile; preserve the exact extracted command line and digest. Do not infer UKI contents from source configuration. |
| UKI contents | Generated UKI SHA-256 and PE section extraction | Isolated P0 ISO UKI SHA-256: `883a79fcaf70b042d074c4ad0e1e5876ee1365ff541367ed72eeb619d84f278b`. This is a dirty-tree development artifact. | BLOCKED | Rebuild from clean commit; bind kernel, initrd, command line and release manifest. |
| UKI signature | `sbverify --cert <approved-db-cert> <UKI>` | No organization DB certificate or production-signed UKI was supplied. The P2 trust gate could not run SB-01/SB-02. | BLOCKED | Independent key custody, approved certificate, signature verification and negative wrong-key/unsigned UKI evidence. Development keys are explicitly excluded. |
| Secure Boot verification | OVMF enrolled with approved DB, then read-only physical `SecureBoot-*` variable | No enrolled production OVMF test or physical observation. | BLOCKED | Positive signed boot and rejection of altered/unsigned UKI with Secure Boot still enabled. |
| Measured boot | Physical TPM PCR 0,4,7,11 + quote | No physical TPM quote; software TPM is development-only. | BLOCKED | Fresh server nonce, TPM2 quote, AK signature, selected-PCR verification, hardware identity record. |
| dm-verity root hash | Release verity manifest, hash tree/rootfs, signed UKI command line; `veritysetup verify` | P0 evidence uses an ext4 root partition. No supplied production squashfs/hash-tree/root-hash binding. P2 gate blocked SB-04..SB-06. | BLOCKED | Generate rootfs/hash tree, verify clean and corrupt rejection, and bind the exact root hash into the signed UKI. |
| TPM quote | `tpm2_checkquote`, server TPMS_ATTEST/AK verification | C verifier and software-TPM credential-activation smoke exist; no hardware evidence. | BLOCKED | Hardware quote tied to approved enrolled AK/EK identity and release PCR policy. |
| Event-log replay | [`tools/examos-eventlog-replay.py`](../../tools/examos-eventlog-replay.py) plus raw `binary_bios_measurements` SHA-256 | TCG2/SHA-256 fixture replay passes; raw physical firmware log unavailable. | BLOCKED | Replay the captured hardware log, compare PCR 0/4/7/11 with verified quote, preserve hashes and parser version. |
| Production authorization | Signed production device/release registries, EK chain, approved release policy and server key-release decision | Signed-registry tamper gate passes with ephemeral test keys. No organization trust anchor, EK chain, hardware enrollment or signed release policy. | BLOCKED | Approved registry signing ceremony, EK-chain validation, AK credential activation, and independent release authorization. |

## Current test facts

- Isolated P0 ISO build and QEMU USB-emulation boot passed, but this is dirty
  development evidence. The boot log reaches a serial login prompt, not a
  release locked-kiosk proof.
- `tests/p2/p2-secureboot-gate.sh` was run against isolated temporary paths:
  SB-03 failed because the available UKI lacked `lockdown=confidentiality`;
  SB-01/SB-02 and SB-04..SB-06 were blocked by absent production signing and
  verity inputs.
- `tests/p3/production-registry.sh` verifies positive and negative signed
  registry behavior with ephemeral test keys. It does not certify trust-anchor
  custody or production deployment.
- `tests/p3/test-eventlog-replay.py` covers a supported TCG2 fixture and
  malformed/truncated input. It does not authenticate firmware measurements.

## Candidate closure packet

Before hardware testing, create a new immutable evidence directory outside the
source tree containing: clean commit ID, release build config and toolchain,
SBOM, rootfs/hash-tree/UKI/image hashes, UKI section dump, approved DB
certificate fingerprint, `sbverify` positive/negative logs, OVMF logs, verity
clean/corruption logs, registry signatures and public-key fingerprints. Each
file must be listed in a SHA-256 manifest signed by the approved release
authority.

Only after that packet passes review may the external-media-only procedure in
[PHYSICAL_DEVICE_TEST_PLAN.md](PHYSICAL_DEVICE_TEST_PLAN.md) proceed. The
physical gate must preserve Windows, internal disks, boot entries, TPM state,
and Secure Boot keys.

`tests/production/collect-boot-chain-evidence.sh` performs the artifact-level
collection and hashing portion of this packet. It returns BLOCKED when any
required release artifact is absent and does not create test keys or modify
the supplied artifacts.
