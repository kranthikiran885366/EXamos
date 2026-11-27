# ExamOS / SPPIO Mass Lab PXE / iPXE Netboot Guide

## Overview
Boot 50+ lab workstations simultaneously over Gigabit Ethernet without creating or swapping USB sticks.

## Server Prerequisites (Local Lab Provisioning Server)
1. **DHCP + TFTP (`dnsmasq`)**: Serve `ipxe.efi` (UEFI x86_64) and chainload `examos.ipxe`.
2. **HTTP Mirror (`nginx` or `caddy`)**: Host the signed release artifacts from `image/output/`:
   - `/examos/current/examos.vmlinuz`
   - `/examos/current/examos.initrd`
   - `/examos/current/examos.raw` (for diskless `rd.live.ram=1` or automated disk deployment)
   - `/examos/current/examos.sha256` and `.sig`

## Security Notes
- UEFI Secure Boot must remain **Enabled** with the institution/SPPIO `db` key enrolled so only signed `ipxe.efi` and `examos.vmlinuz` execute.
- `lockdown=confidentiality` and `iommu=force` are enforced directly on the kernel command line in `examos.ipxe`.
