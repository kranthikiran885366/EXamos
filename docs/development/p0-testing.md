# P0 testing

The P0 gate is narrow and explicit:

- host validation
- required tool validation
- repository validation
- mkosi build
- artifact discovery
- checksum capture
- QEMU + OVMF boot test
- CI pass/fail result

## Commands

```bash
bash ./tests/p0/host-check.sh
bash ./tests/p0/examos-doctor.sh
bash ./tests/p0/repository-check.sh
bash ./scripts/p0.sh
```

If the host is not Linux with KVM and UEFI support, the correct result is BLOCKED/FAIL rather than a fabricated PASS.
