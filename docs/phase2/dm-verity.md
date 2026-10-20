# ExamOS P2 — dm-verity / Read-Only Root

## 1. Overview

The root filesystem is protected by dm-verity. Any modification to the authenticated root blocks at runtime causes the kernel to return I/O errors rather than serving corrupt data, preventing the kiosk from reaching a valid state.

## 2. Build Process

```
mkosi build
  → raw disk image: image/examos.raw
  → dm-verity-setup.sh (post-build, on CI host):
      1. Attach raw image via losetup
      2. Mount root partition read-only
      3. mksquashfs → examos-root.squashfs (zstd compressed)
      4. veritysetup format → examos-root.verity + root hash
      5. Write verity-descriptor.conf
      6. Update phase2-manifest.json
```

## 3. Kernel Command Line

The following parameters are added to the kernel command line after the P3 Secure Boot chain is established. In P2 (TEST_SIGNED builds):

```
root=/dev/mapper/root
rd.dm-verity=1
dm-verity.device=<ROOT_DEV>
dm-verity.verity_roothash=<ROOT_HASH_FROM_MANIFEST>
```

The root hash is derived from the actual image artifact by `dm-verity-setup.sh`. It is recorded in `phase2-manifest.json` under `verityRootHash`.

## 4. Fail-Closed Behavior

When dm-verity detects a mismatch:
- The kernel returns `-EIO` for the corrupt block
- No userspace process can read the corrupt data
- If the root filesystem itself is corrupt, the system fails to mount and does not reach `graphical.target`

## 5. Corruption Test (P2-06)

`image/scripts/dm-verity-corruption-test.sh`:
1. Records the SHA-256 of the clean SquashFS
2. **Copies** the SquashFS to a disposable test location
3. XORs one byte at offset 65537 (past the SquashFS superblock)
4. Runs `veritysetup verify` on the clean copy → must succeed
5. Runs `veritysetup verify` on the corrupted copy → must fail
6. Records both hashes and the `veritysetup` output as evidence

The known-good artifact is never modified.

## 6. P3 Dependency

In P2, the verity root hash in the kernel command line is not cryptographically protected by Secure Boot. The root hash could be replaced by an attacker with physical boot access. P3 addresses this via:
- UKI (Unified Kernel Image) embedding the cmdline
- Secure Boot signing of the UKI
- TPM PCR policy binding decryption keys to the known-good cmdline hash

This dependency is documented; P2 is not claimed to be P3-complete.

## 7. Artifacts

| File | Contents |
|---|---|
| `artifacts/phase2/examos-root.squashfs` | SquashFS root image |
| `artifacts/phase2/examos-root.verity` | dm-verity hash tree |
| `artifacts/phase2/verity-descriptor.conf` | Kernel cmdline fragment |
| `artifacts/phase2/veritysetup-output.txt` | veritysetup format output |
| `artifacts/phase2/dm-verity-clean-boot.txt` | Clean verification evidence |
| `artifacts/phase2/dm-verity-corruption-test.txt` | Corruption test evidence |
