# ExamOS Phase 2 — Dev vs Release Flavour Separation

## 1. Purpose

Phase 2 separates the image into two distinct flavours:

| Flavour | File | Purpose |
|---|---|---|
| Release | `image/mkosi.conf` | Candidate-facing image; must meet all P2 acceptance gates |
| Dev/Test | `image/mkosi.dev.conf` | Engineering diagnostics only; never distributed to candidates |

## 2. Release Flavour Constraints

The release image (`image/mkosi.conf`) must NOT contain:

- Interactive shell: `bash`, `sh`, `dash`, `zsh`, or any shell with a login path
- SSH client or server (`openssh-server`, `openssh-client`, `sshd`)
- Package manager: `apt`, `apt-get`, `dpkg` CLI (dpkg libraries may remain as dependencies)
- Compiler or linker: `gcc`, `g++`, `ld`, `make`, `cmake`
- General scripting runtime not required by the runtime: `python3`, `perl`, `ruby`, `node`
- Privilege escalation: `sudo`, `su`, `pkexec`
- Debug tools: `gdb`, `strace`, `ltrace`, `valgrind`
- Desktop environment: no GNOME, KDE, XFCE, LXDE, LightDM, GDM3
- General file manager, task panel, application launcher
- Development tokens, test keys, debug endpoints

## 3. Allowed Release Packages (Explicit Allowlist)

| Package | Justification |
|---|---|
| `linux-image-amd64` | Kernel |
| `systemd`, `systemd-boot`, `systemd-boot-efi` | Init, bootloader |
| `udev`, `dbus` | Device management, IPC |
| `cage` | Wayland kiosk compositor (single-app) |
| `chromium` | Exam browser |
| `fonts-liberation`, `fontconfig`, `xkb-data` | Rendering and input layout |
| `pipewire`, `wireplumber`, `pipewire-pulse` | Audio pipeline (proctoring P4 prep) |
| `tpm2-tools`, `libtss2-tcti-device0` | TPM2 interaction (P3 requirement) |
| `network-manager`, `wpasupplicant`, `iw` | Network |
| `ca-certificates`, `openssl`, `libssl3`, `libcurl4` | TLS, certificate validation |
| `nftables` | Firewall |
| `apparmor`, `apparmor-utils` | MAC profiles for Chromium |
| `libudev1` | udev library (udev dependency) |
| `pulseaudio-utils`, `v4l-utils` | A/V device utilities (UVC webcam, audio) |
| `libgl1-mesa-dri` | GPU/display |
| `kbd` | Keyboard handling |
| `cryptsetup-bin` | dm-verity / veritysetup (P2) |
| `usbguard` | USB device authorization (P2) |
| `squashfs-tools` | SquashFS image creation (build-time; may be removed from runtime) |

Any package not in this list requires a written justification and must pass release-audit.sh.

## 4. Dev Flavour Additions

The dev flavour (`image/mkosi.dev.conf`) adds diagnostics not permitted in release:

- `bash`, `util-linux`, `procps`, `iproute2` — diagnostic shell
- `iputils-ping`, `nmap` — network testing
- `strace` — process tracing
- `less`, `vim-tiny` — viewing
- `curl`, `wget` — manual testing
- `openssh-client` — remote access during engineering
- `systemd-coredump` — crash analysis (disabled in release)
- `kmod` — module management

Dev flavour uses `lockdown=integrity` (not `confidentiality`) and sets `examos.flavour=dev` on the kernel command line.

## 5. CI Gate Enforcement

The release-audit script (`image/scripts/release-audit.sh`) is run in CI against every release build:

```bash
ROOTFS_PATH=/path/to/mounted/rootfs \
AUDIT_OUT=artifacts/phase2/release-package-audit.json \
bash image/scripts/release-audit.sh
```

The script:
1. Checks for prohibited binaries by searching the mounted rootfs filesystem
2. Checks for prohibited service enablement
3. Verifies no SSH server config files present
4. Validates Chromium policy correctness
5. Validates nftables policy
6. Produces machine-readable `release-package-audit.json`
7. Exits non-zero on any FAIL finding, blocking CI promotion

## 6. Build Commands

```bash
# Release image (default — CI uses this)
cd image && sudo mkosi build

# Dev image (engineering use only)
cd image && sudo mkosi --config mkosi.dev.conf build

# Audit release image rootfs (after mounting)
ROOTFS_PATH=/mnt/rootfs \
AUDIT_OUT=artifacts/phase2/release-package-audit.json \
bash image/scripts/release-audit.sh
```

## 7. Identification

The running image identifies its flavour through:
- `/etc/os-release` `BUILD_ID` field (`p2-release` or `p2-dev`)
- Kernel command line `examos.flavour=release|dev` parameter
- `/proc/cmdline` inspection by diagnostic tooling

A candidate-facing image with `examos.flavour=dev` in `/proc/cmdline` must be rejected by deployment automation.
