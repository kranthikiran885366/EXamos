# ExamOS P0 release record

## 1. Objective

Establish the reproducible development foundation for ExamOS, including host validation, repository structure, mkosi configuration, build workflow, artifact collection, and a boot test under QEMU with OVMF.

## 2. Environment

Observed environment facts:

- OS: MINGW64_NT-10.0-26200
- Architecture: x86_64
- UEFI: no
- /dev/kvm: missing
- free space on C:: 4.7G available
- virtualization extensions: not detected in /proc/cpuinfo

These entries are actual outputs from the current environment and show that the host is not a valid Linux build host for P0.

## 3. Tool versions

- git: 2.52.0.windows.1
- mkosi: command not found
- qemu-system-x86_64: command not found
- swtpm: command not found
- tpm2_pcrread: command not found
- sbsign: command not found
- veritysetup: command not found
- mksquashfs: command not found

## 4. Repository

The repository contains the source skeleton and documentation for the P0 workflow, but it is intentionally not claiming a successful build because the required host prerequisites are absent.

## 5. Build process

Not executed successfully because the host is not a supported Ubuntu/Debian Linux build host with KVM and UEFI support.

## 6. Artifact

No valid ExamOS image artifact was produced in this environment.

## 7. QEMU/OVMF result

Not executed successfully; QEMU and OVMF were not available in the environment.

## 8. CI result

Not run because the required build host conditions are absent.

## 9. Reproducibility result

Not established in this environment.

## 10. Known issues

- Windows/MSYS environment instead of Linux build host
- /dev/kvm missing
- no UEFI firmware
- no QEMU/mkosi toolchain installed
- insufficient free space on the working filesystem

## 11. Limitations

P0 is not yet complete in this environment. Future work must be performed on a real Linux host with KVM and UEFI support before P0 can be demonstrated and tagged.

## 12. Gate decision

P0 = NOT COMPLETE

The project records the actual failure state rather than fabricating a pass.
