# ExamOS P0 requirements

## Host requirements

P0 requires a real Linux build host, not a Windows/MSYS environment.

- Linux x86_64 host
- KVM enabled
- /dev/kvm available
- UEFI firmware available
- at least 50 GB free space on the build filesystem
- git, mkosi, qemu-system-x86_64, swtpm, TPM tools, and related build helpers installed

## This environment

The current workspace is running on a Windows host and is not a supported build host for P0. This fact is recorded as actual evidence and the project intentionally fails closed.
