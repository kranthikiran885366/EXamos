# ExamOS Phase 1 (P1) — Troubleshooting Guide

## 1. Observed Build & Runtime Issues

### Issue 1: `xkeyboard-config` Package Missing in Debian Trixie
- **Symptom**: `mkosi build` failed with `E: Unable to locate package xkeyboard-config`.
- **Root Cause**: In Debian 13 (trixie), the package containing XKB keyboard layouts is named `xkb-data`.
- **Resolution**: Updated `image/mkosi.conf` package list to use `xkb-data`.

### Issue 2: Drvfs Filesystem / WSL Permission Conflicts
- **Symptom**: `chmod` or `mkdtemp` failures when running under `/mnt/d/` on Windows-hosted WSL filesystems.
- **Root Cause**: Windows drvfs does not support all native Linux POSIX permission and namespace semantics by default.
- **Resolution**: Executed all image build and root tasks within native ext4 mounts or with explicit root ownership handling in mkosi build scripts.

### Issue 3: Missing `xorriso` on Build Host
- **Symptom**: `build-iso.sh` returned command not found.
- **Root Cause**: `xorriso` was required for generating hybrid bootable ISO images from raw disk images.
- **Resolution**: Installed `xorriso` package and verified output generation.

---

## 2. Diagnostics & Recovery Commands

```bash
# Check systemd service status in running VM or test environment
systemctl status examos-kiosk
systemctl status examos-server
systemctl status examos-agent

# Inspect system logs
journalctl -u examos-kiosk.service --no-pager -n 50
journalctl -u examos-server.service --no-pager -n 50

# Test local server API
curl -s http://127.0.0.1:8000/api/v1/health
curl -s http://127.0.0.1:8000/api/v1/status
curl -s http://127.0.0.1:8000/api/v1/ledger
```
