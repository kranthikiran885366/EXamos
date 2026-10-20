# ExamOS P3 Secure Boot

## Overview

ExamOS P3 enforces Secure Boot to ensure only a signed ExamOS Unified Kernel Image (UKI) can boot on enrolled machines. Any modification to the UKI, kernel, initrd, or command line results in a PCR mismatch that the attestation server rejects.

## Key Hierarchy

```
Platform Key (PK)
    └── Key Exchange Key (KEK)
          └── Signature Database (db)
                └── ExamOS db signing certificate
                      └── Signed UKI (.efi)
PCR policy signing key (independent)
```

### Platform Key (PK)

- Root of UEFI Secure Boot trust
- Signs KEK updates
- One per deployment environment
- Production: offline HSM, never in Git or CI

### KEK

- Signs updates to the signature database (db)
- Production: offline HSM

### db (Signature Database)

- Contains the ExamOS signing certificate
- UEFI verifies the UKI signature against this database

### UKI Signing Key

- Used to sign the Unified Kernel Image
- Production: offline, controlled signing process
- Development: `image/trust/db.key` (TEST ONLY)

### PCR Policy Signing Key

- Separate from UKI signing key
- Used for future TPM PCR policy binding
- Production: offline HSM

## Development Key Generation

```bash
bash image/trust/generate-dev-keys.sh
```

Generates RSA-2048 self-signed test keys valid for 3650 days. All private keys get `chmod 600`. Keys are `.gitignore`d.

## Signing a UKI (Development)

```bash
# Sign with development db key
sbsign \
    --key image/trust/db.key \
    --cert image/trust/db.crt \
    --output build/examos.efi \
    build/examos.unsigned.efi

# Verify
sbverify --cert image/trust/db.crt build/examos.efi
```

## OVMF Secure Boot Test Environment

```bash
# Copy OVMF vars (never overwrite the host template)
cp /usr/share/OVMF/OVMF_VARS.fd /tmp/examos-ovmf-vars.fd

# Enroll test keys into the OVMF vars copy
python3 /usr/lib/python3/dist-packages/ovmfkeyenroll.py \
    --pk   image/trust/PK.crt  \
    --kek  image/trust/KEK.crt \
    --db   image/trust/db.crt  \
    --ovmf /tmp/examos-ovmf-vars.fd

# Launch QEMU with the modified vars
qemu-system-x86_64 \
    -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE.fd \
    -drive if=pflash,format=raw,file=/tmp/examos-ovmf-vars.fd \
    ...
```

## PCR 7 — Secure Boot Policy Measurement

PCR 7 captures the UEFI Secure Boot state:

| Scenario | PCR 7 |
|----------|-------|
| Secure Boot enabled, correct db | Matches golden value |
| Secure Boot disabled | All-zeros (rejected) |
| Wrong db certificate enrolled | Different hash (rejected) |
| Extra test certificate enrolled | Different hash (rejected) |

The attestation server compares PCR 7 against the registered golden value for the release. Any deviation fails Check 12–13.

## Verifying Secure Boot State Inside the Guest

```bash
# Via mokutil
mokutil --sb-state

# Via EFI variables
cat /sys/firmware/efi/efivars/SecureBoot-*

# Via systemd
bootctl status | grep "Secure Boot"
```

## Production Key Rotation

Key rotation requires a controlled procedure:

1. Generate new db signing key/cert (offline)
2. Sign new cert with KEK
3. Deploy new db update to enrolled machines
4. Re-sign all UKI artifacts with new key
5. Generate new golden PCRs from a clean measured boot of the re-signed image
6. Update the release registry with new PCR values
7. Register as a new release_id (do not overwrite golden values in place)
8. Retire the old release_id after all machines have migrated
