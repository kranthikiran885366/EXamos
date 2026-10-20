# ExamOS Phase 2 — Lockdown Architecture

## 1. Overview

Phase 2 transforms the minimal kiosk built in Phase 1 into a hardened examination appliance by activating enforcement of the security controls whose configurations were staged in P1 and adding new controls required by the P2 contract.

The frozen P1 boot path is preserved: UEFI → systemd-boot → kernel → systemd → Cage → Chromium kiosk.

## 2. Boot Chain with P2 Controls

```
UEFI / OVMF (P3: Secure Boot signing — not P2 scope)
   │
   ▼
systemd-boot (ESP partition)
   │
   ▼
Linux Kernel
  cmdline: lockdown=confidentiality module.sig_enforce=1
           intel_iommu=on amd_iommu=on iommu=pt noswap
           init_on_alloc=1 init_on_free=1 slab_nomerge
           pti=on spectre_v2=on vsyscall=none
   │
   ▼
systemd (PID 1)
   │
   ├─► local-fs.target
   │     └─ tmp.mount (tmpfs, noexec,nosuid,nodev)
   │     └─ home-exam.mount (tmpfs, noexec,nosuid,nodev)
   │     └─ var-log.mount (tmpfs)
   │
   ├─► sysinit.target
   │     └─ examos-dev-shm-hardening.service
   │           └─ verify /dev/shm API tmpfs (exec,nosuid,nodev)
   │     └─ examos-usb-lockdown.service → authorized_default=0 on all USB buses
   │
   ├─► network-pre.target
   │     └─ nftables.service (BEFORE NetworkManager — fail-closed)
   │
   ├─► multi-user.target
   │     └─ examos-server.service
   │     └─ examos-agent.service
   │     └─ apparmor.service
   │     └─ usbguard.service
   │
   ├─► graphical.target
   │     └─ examos-module-lock.service → kernel.modules_disabled=1
   │     └─ examos-preflight.service (p2-startup-validator.sh)
   │     │       fails → examos-lockdown-failed.target → kiosk blocked
   │     └─ examos-kiosk.service (User=exam, hardened, after preflight)
   │     └─ examos-kiosk-readiness.service (live Cage/Chromium/Wayland checks)
   │           └─ cage -s -- examos-kiosk-launcher
   │                 └─ Chromium --kiosk --app=<EXAM_URL>
   │                       (managed policy: URLBlocklist=*, exam-origin only)
   │
   └─ [All getty/autovt/serial/emergency targets: MASKED]
```

## 3. Security Control Layers

| Layer | Control | Implementation |
|---|---|---|
| Kernel | lockdown=confidentiality | KernelCommandLine in mkosi.conf |
| Kernel | module.sig_enforce=1 | KernelCommandLine |
| Kernel | IOMMU DMA remapping | intel_iommu=on amd_iommu=on |
| Kernel | noswap | KernelCommandLine |
| Kernel | Memory zeroing | init_on_alloc=1 init_on_free=1 |
| Runtime | module loading disabled | examos-module-lock.service |
| Runtime | IPv6 disabled | sysctl.d/99-examos-security.conf |
| Runtime | SysRq disabled | sysctl |
| Runtime | ptrace scope=3 | sysctl |
| Runtime | BPF unprivileged off | sysctl |
| Runtime | core dumps off | coredump.conf + sysctl |
| Filesystem | root read-only | dm-verity (post-build) |
| Filesystem | /tmp noexec | tmp.mount (tmpfs) |
| Filesystem | /home/exam noexec | home-exam.mount (tmpfs) |
| Filesystem | /dev/shm exec,nosuid,nodev | examos-dev-shm-hardening.service |
| Filesystem | /var/log ephemeral | var-log.mount |
| Network | default-deny | nftables.conf |
| Network | before-network ordering | nftables.service.d/p2-ordering.conf |
| Network | fail-closed on stop | ExecStopPost in nftables override |
| USB | authorized_default=0 | examos-usb-lockdown.service |
| USB | per-device policy | USBGuard rules.conf + udev rules; daemon and live policy interface required by preflight |
| Browser | URL lockdown | Chromium managed policy p2.1 |
| Browser | camera/mic scoped | VideoCaptureAllowedUrls / AudioCaptureAllowedUrls |
| Browser | sandbox active | No --no-sandbox in launcher |
| MAC | Chromium confinement | AppArmor enforce mode |
| Login | getty/autovt masked | 03-p2-lockdown.sh |
| Login | SSH absent+masked | 03-p2-lockdown.sh |
| Login | sudo/su removed | 03-p2-lockdown.sh |
| Login | root locked | 03-p2-lockdown.sh |
| Preflight | config validation | examos-preflight.service |
| Disk | no internal mounts | No fstab entries; no automount |

## 4. Fail-Closed Behavior

Every mandatory control has a fail-closed path:
- `examos-module-lock.service` failure → `OnFailure=examos-lockdown-failed.target` → kiosk blocked
- `examos-preflight.service` failure → `OnFailure=examos-lockdown-failed.target`
- USBGuard inactive or its live policy interface unavailable → preflight fails; kiosk blocked
- `nftables.service` stop → `ExecStopPost` installs emergency default-deny table
- `nftables.service` syntax error → `ExecStartPre` dry-run fails → NetworkManager never starts
- Chromium crash → `Restart=on-failure` respawns kiosk; never falls to shell

## 5. Phase Boundaries

P2 configures and tests real enforcement. It does NOT implement:
- P3: Secure Boot signing of UKI/kernel, TPM PCR policy, attestation, key release
- P4: Proctoring media capture, WebRTC, detection inference
