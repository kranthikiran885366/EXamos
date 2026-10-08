# Troubleshooting

## /dev/kvm missing

- Ensure virtualization is enabled in BIOS/UEFI
- Confirm the host is running a KVM-capable kernel
- Recheck that the user has access to the `kvm` group

## OVMF missing

```bash
sudo apt install ovmf
```

## mkosi namespace failures

Current mkosi can require user namespace access on Ubuntu. If the build reports namespace errors, verify AppArmor and user namespace settings on the dedicated build host.

## Image build failure

- Re-run `mkosi -f` in the `image` directory
- Check the tool versions, especially `mkosi`, `debootstrap`, and `systemd`
- Validate that the build host has sufficient free space

## QEMU boot failure

- Confirm OVMF is present
- Verify the image artifact was created
- Try `mkosi vm` in the image directory for debug output
