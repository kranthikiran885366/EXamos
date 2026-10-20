# ExamOS Phase 2 Pre-Change Audit

Generated: 2026-10-09  
Purpose: Mandatory repository inspection before any Phase 2 modifications per §2 of the implementation contract.

---

## Repository Commit

```
c8d8c61 (HEAD -> master) ExamOS P0: Enterprise certification suite passing (Grade A, 63 dynamic checks)
```

Prior tagged commits:
- `v0.2.0` → Phase 1 finalized (ExamOS 0.2.0, kiosk gate PASS)
- `v0.1.0` → Phase 0 complete

---

## Build Host and OS

- Host OS: Linux 6.6.87.2-microsoft-standard-WSL2 x86_64 (GitHub Actions: ubuntu-latest)
- RAM: 3.7 GiB (CI runner)
- CPU: 8 vCPUs
- Storage free: 947 GB

---

## Build Tooling / Version

| Tool | Version |
|---|---|
| mkosi | 26 |
| QEMU | 10.2.1 (Debian 1:10.2.1+ds-1ubuntu3.2) |
| swtpm | 0.10.1 |
| gcc (host) | 15.2.0 |
| g++ (host) | 15.2.0 |
| veritysetup | 2.8.4 (from P0 toolchain matrix) |
| sbsign | 0.9.4 |
| openssl | 3.5.5 |
| jq | system |

Build command: `cd image && sudo mkosi build`  
Build config: `image/mkosi.conf` (single config, no profile separation yet)

---

## Target Image / Flavour

- Distribution: Debian Trixie (13), x86-64
- Format: disk (raw)
- Output file: `image/examos.raw` (also `image/examos.raw.raw` in some CI runs)
- Image size (P1): 2.2 GiB (2,307,629,056 bytes)
- Bootloader: systemd-boot (UEFI)
- Current flavour separation: `image/dev.conf` and `image/release.conf` exist but are NOT wired into mkosi.conf. `image/config/dev.conf` and `image/config/release.conf` exist as sourcing targets for scripts only. No mkosi `Profile` blocks separate dev from release at build time.

---

## Kernel Version / Config

- Package: `linux-image-amd64` from Debian Trixie (exact version resolved at build time)
- Architecture: x86-64 (UEFI)
- Current kernel command line (from `image/mkosi.conf`):
  ```
  console=tty0 console=ttyS0 quiet systemd.log_target=console
  systemd.log_level=info systemd.firstboot=0
  systemd.unit=graphical.target lockdown=integrity
  systemd.unified_cgroup_hierarchy=1
  ```
- **Lockdown mode: `integrity`** — NOT `confidentiality`. Upgrading to `confidentiality` is P2 scope.
- **dm-verity**: NOT configured (no `veritysetup` package in mkosi.conf, no boot parameters).
- Module-signature enforcement: set in kernel build defaults for Debian Trixie (CONFIG_MODULE_SIG_FORCE depends on lockdown mode; Debian Trixie kernel enforces signatures when `lockdown=integrity`).
- IOMMU: not explicitly enabled in cmdline (no `intel_iommu=on` / `amd_iommu=on`).
- kexec: not explicitly disabled in cmdline.
- IPv6: not disabled in cmdline; partial network sysctl protection applied.

---

## Chromium Version

- Package: `chromium` from Debian Trixie
- Exact version: resolved at image build time (Debian Trixie chromium package, 2025/2026 Trixie series, approximately Chromium 130+)
- Policy path: `/etc/chromium/policies/managed/examos_policies.json`
- Also symlinked to: `/etc/opt/chrome/policies/managed/examos_policies.json`

**Known policy issues found in pre-change audit:**
1. `URLAllowlist` contains `"https://*"` — this allows ALL HTTPS destinations, defeating the intent of the URL allowlist. This is a P2 mandatory fix.
2. `AudioCaptureAllowed: true` and `VideoCaptureAllowed: true` — these are global grants, not scoped to exam origin. Contract requires `AudioCaptureAllowedUrls` and `VideoCaptureAllowedUrls` scoped to exam origin only. P2 mandatory fix.
3. `DefaultPopupsSetting` not present — must be added (value 2 = block).
4. `AllowFileSelectionDialogs` not present — must be added (false).
5. `URLAllowlist` allows `http://127.0.0.1:8000/*` and `http://localhost:8000/*` — review required; these bypass HTTPS enforcement.

---

## P1 Kiosk Service

- **Service file**: `image/overlay/etc/systemd/system/examos-kiosk.service`
- **User**: `exam` (UID 1000, shell `/usr/sbin/nologin`)
- **ExecStart**: `/usr/bin/cage -s -- /usr/local/bin/examos-kiosk-launcher`
- **Compositor**: Cage (Wayland kiosk compositor)
- **Launcher binary**: `kiosk/launcher/launcher.c` → compiled to `/usr/local/bin/examos-kiosk-launcher`
- **WantedBy**: `graphical.target`
- **Restart**: `on-failure`, RestartSec=5
- **Chromium flags**: `--kiosk --app=<EXAM_URL>` — no `--no-sandbox` (verified P1 kiosk check)
- **Ephemeral profile**: `mkdtemp("/run/user/1000/examos_kiosk_XXXXXX")` — RAM-backed

**P1 gate result**: PASS (all 10 checks, including kiosk_config, network_config, no_desktop, exam_user, kiosk_runs_as_exam, no_secrets)

---

## Network Manager

- **Backend**: `network-manager` (NetworkManager) + `wpasupplicant`
- No `systemd-networkd` standalone.
- No `NetworkManager.conf` in overlay — uses package defaults.

---

## Firewall Backend

- **Backend**: `nftables` (package installed, service enabled in `01-hardening.sh`)
- **Config**: `image/overlay/etc/nftables.conf`
- **Policy**: default DROP on input/forward/output
- **Allowed outbound**: DNS (UDP/TCP 53), HTTPS (TCP 443), HTTP (TCP 80), NTP (UDP 123), DHCP, loopback, established/related
- **P1 status**: Config present; runtime enforcement not validated — P2 scope per `image/config/p1.conf`
- **Gap**: No destination restriction on TCP 443 (any HTTPS host allowed). P2 must restrict to exam server hosts/IPs.
- **Gap**: No DNS pinning to controlled resolver (any DNS on port 53 allowed). P2 must restrict.

---

## Filesystem / Root Layout

- Root filesystem format: `disk` (raw) via mkosi — **NOT SquashFS yet** (dm-verity not configured)
- Bootable: yes (systemd-boot, EFI)
- Current writable layout: no explicit tmpfs units; `/tmp` and `/run` managed by systemd defaults
- No `/home/exam` tmpfs unit
- No `/dev/shm` explicit restrictions
- Swap: `vm.swappiness=10` in sysctl (not disabled; no explicit `swapoff` or zram removal)
- Core dumps: `kernel.core_pattern = |/bin/false` and `fs.suid_dumpable = 0` (partial hardening; systemd coredump service state not audited)

---

## USB Authorization Method

- **Mechanism**: udev rules (`image/overlay/etc/udev/rules.d/99-examos-usb-lockdown.rules`)
- **Approach**: Per-class interface authorization via `ATTR{bInterfaceClass}` and `ATTR{authorized}` sysfs
- **Gap**: No `authorized_default=0` set for USB buses — unrecognized device classes are NOT denied by default
- **Gap**: Composite device (HID + storage) will be authorized if HID interface is seen first (class-level matching is not interface-level)
- **No USBGuard** installed or configured — udev-only mechanism

---

## Existing Tests

| Directory | Status | Notes |
|---|---|---|
| `tests/p0/` | Complete | host-check, doctor, repository-check, build, boot, enterprise validation |
| `tests/p1/` | Complete | kiosk, network, boot, gate, performance, validate-source, collect-artifacts |
| `tests/p2/` | **Empty** | Only `.gitkeep` — no P2 tests exist |
| `tests/p3/` | Partial | attestation-suite, gate, collect-artifacts, test-matrix.yaml |
| `tests/p4/` | Empty | — |
| `tests/phase4/` | Separate | phase4 artifacts exist, different structure |

---

## Known Failures

1. **`examos-server.service` fails at runtime** — binary not deployed to image at build time (compiled separately via `make all`; not copied into mkosi overlay). Boot log shows "Failed to load environment files" and service activation failure.
2. **`examos-agent.service` fails at runtime** — same root cause as server: binary not in image overlay.
3. **`examos-kiosk.service` fails** — depends on server which fails; kiosk never reaches Cage/Chromium stage in full boot.
4. **Exam URL is `NOT_CONFIGURED`** — P1 gate reports this as `BLOCKED` (not hard failure), but kiosk launcher exits immediately when URL is not configured.
5. **`lockdown=integrity` not `confidentiality`** — per p1.conf comment, `confidentiality` is P2 scope.
6. **dm-verity absent** — explicitly noted as "Not started" in p1-overview.md.
7. **Chromium policy URLAllowlist = `https://*`** — allows all HTTPS, defeats lockdown intent.
8. **No swap-off enforcement** — `vm.swappiness=10` reduces but does not disable swap.
9. **USB authorized_default not set** — unknown device classes not blocked by default.
10. **No tmpfs mount units** for `/tmp`, `/home/exam`, `/dev/shm` with `noexec,nosuid,nodev`.

---

## Files to Modify (Phase 2)

| File | Change |
|---|---|
| `image/mkosi.conf` | Add packages: `cryptsetup-bin` (veritysetup), `usbguard`, `systemd-coredump`; update KernelCommandLine: `lockdown=confidentiality`, dm-verity params, `intel_iommu=on amd_iommu=on`, `noswap`, `module.sig_enforce=1`; add `BuildScripts` reference |
| `image/overlay/etc/os-release` | Update `PRETTY_NAME`, `VERSION`, `BUILD_ID=p2` |
| `image/overlay/etc/chromium/policies/managed/examos_policies.json` | Fix URLAllowlist (remove `https://*`); add origin-scoped camera/mic; add DefaultPopupsSetting, AllowFileSelectionDialogs |
| `image/overlay/etc/nftables.conf` | Restrict TCP 443 to exam server IPs/hosts; add DNS pinning to controlled resolver |
| `image/overlay/etc/sysctl.d/99-examos-security.conf` | Add `net.ipv6.conf.all.disable_ipv6=1`, `kernel.modules_disabled=1` (managed via late-boot unit), swap/core controls |
| `image/overlay/etc/systemd/system/examos-kiosk.service` | Add systemd hardening directives (NoNewPrivileges, ProtectSystem=strict, etc.) |
| `image/scripts/01-hardening.sh` | Add USB authorized_default, AppArmor enforce mode, verity setup, module lock service |

## Files to Create (Phase 2)

| File | Purpose |
|---|---|
| `image/scripts/03-p2-lockdown.sh` | New build script for P2 lockdown controls |
| `image/overlay/etc/systemd/system/examos-module-lock.service` | Late-boot module loading disable |
| `image/overlay/etc/systemd/system/examos-usb-guard.service` | USB authorization enforcement |
| `image/overlay/etc/usbguard/rules.conf` | USBGuard policy |
| `image/overlay/etc/systemd/system/tmp.mount` | tmpfs for /tmp noexec,nosuid,nodev |
| `image/overlay/etc/systemd/system/home-exam.mount` | tmpfs for /home/exam |
| `image/overlay/etc/systemd/system/dev-shm.mount` | /dev/shm restrictions |
| `image/overlay/etc/systemd/coredump.conf` | Disable coredump storage |
| `image/overlay/etc/examos/p2-config.conf` | P2 configuration schema |
| `image/scripts/p2-startup-validator.sh` | Runtime config validation |
| `image/scripts/release-audit.sh` | Release image content audit |
| `image/scripts/dm-verity-setup.sh` | dm-verity hash generation |
| `tests/p2/*.sh` | All P2 test scripts (P2-01 through P2-20) |
| `.github/workflows/p2.yml` | P2 CI workflow |
| `docs/phase2/*.md` | All Phase 2 documentation |
| `artifacts/phase2/` | All Phase 2 evidence artifacts |

## Files Intentionally NOT to Modify

| File | Reason |
|---|---|
| `kiosk/launcher/launcher.c` | P1 frozen; launcher works correctly; no sandbox-disabling flags present |
| `agent/main.c` | P3/P4 scope; do not touch |
| `server/` | Backend; P2 does not rewrite backend |
| `.github/workflows/p0.yml` | P0 gate must remain unchanged |
| `.github/workflows/p1.yml` | P1 gate must remain unchanged (only extend for P2 regression) |
| `tests/p0/`, `tests/p1/` | Must not modify existing P0/P1 test scripts |
| `image/trust/` | P3 Secure Boot key generation; not P2 scope |
| `image/overlay/etc/systemd/system/examos-proctor.service` | P4 scope; remains disabled |
