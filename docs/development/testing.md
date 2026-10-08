# Testing

P0 should establish a machine-readable gate that checks:

- architecture
- KVM availability
- QEMU capability
- OVMF firmware
- mkosi presence
- TPM tooling
- build success
- artifact generation
- QEMU boot viability

## Example commands

```bash
bash ./tests/p0/host-check.sh
bash ./tests/p0/build.sh
bash ./tests/p0/collect-build-info.sh
bash ./scripts/p0.sh
```

## Expected result

P0 is considered green when the clean workflow builds the image, records artifact metadata, and completes the automated checks without error.
