# ExamOS — Stage 1 evidence record

**Stage:** 1 (Dynamic URL remediation)
**Date:** 2026-10-17
**Branch:** `work/p0-secure-release-remediation-20261011`
**HEAD at edit:** `c8d8c6149458e9c1611966d5f2db66ed2f42e2d1` (working tree dirty)
**Pre-edit backup:** `D:\SEB BRO-stage1-backup-20261017-222900\` (SHA-256 manifest: stage1-pre-edit-manifest.txt)
**Verification script:** `artifacts/evidence/stage0-inspect-20261017-215333/stage1-verify.sh`
**Verification result:** ALL 11 CHECKS PASSED

---

## What was missing (gap this stage closes)

Stage 0 gap-matrix finding §3, items 1–2:

1. `image/overlay/etc/examos/exam.conf` shipped `EXAM_URL=https://exam.examos.security/` —
   a hardcoded universal exam domain embedded in the image, violating the dynamic-URL rule.

2. `image/overlay/etc/chromium/policies/managed/examos_policies.json` and
   `image/overlay/etc/opt/chrome/policies/managed/examos_policies.json` hardcoded
   `exam.examos.security` in URLAllowlist, VideoCaptureAllowedUrls, and AudioCaptureAllowedUrls.
   Changing EXAM_URL via the admin dashboard had no effect on these policies, so camera/audio
   capture permissions were permanently locked to the wrong domain.

   The `/opt/chrome` variant also contained `"https://*"` in URLAllowlist (allows all HTTPS
   navigation) and global `AudioCaptureAllowed: true` / `VideoCaptureAllowed: true` — both
   over-broad security misconfigurations now corrected.

---

## Changes made

### 1. `image/overlay/etc/examos/exam.conf`
- BEFORE SHA-256: `D5BA5F0F55FA53F63B7E0AF1354FD2785ACFD630CFF369C9A2121123A83EC99A`
- AFTER  SHA-256: `2C9BEAACF5C176C30E557CFF7F0A440C810DDF060622E864D7CB82D07716893F`
- Change: `EXAM_URL=NOT_CONFIGURED` (fail-closed). Image ships with no universal domain.

### 2. `image/overlay/etc/chromium/policies/managed/examos_policies.json`
- BEFORE SHA-256: `D96827EA3492FF40A1C53BE03472D1CBA2A73644CC7A38251051BC10629C2F18`
- AFTER  SHA-256: `C9B7D9C4F12E0EBE79E07006B7B85E82E071F2736DA745C2AF1179A7F4BC5EC5`
- Change: removed `exam.examos.security/*` and `*.examos.security/*` from URLAllowlist,
  VideoCaptureAllowedUrls, AudioCaptureAllowedUrls. Only `http://127.0.0.1:8000/*` (loopback
  admin server) remains. The generator injects the provisioned exam origin at boot time.

### 3. `image/overlay/etc/opt/chrome/policies/managed/examos_policies.json`
- BEFORE SHA-256: `FB83FCA5363D5D2A874C3C4A95B2298C03C77C9E74A0B3726B98C9E9C210130B`
- AFTER  SHA-256: `07709521D69F45EDBF4B6FE0B66FB72756CB417542519CFEC81DACB9C027BCAD`
- Change: (a) removed `"https://*"` catch-all allowlist, (b) removed `AudioCaptureAllowed: true`
  and `VideoCaptureAllowed: true` global keys (replaced with per-origin lists), (c) removed
  hardcoded `exam.examos.security` domains. Only loopback entries remain; generator injects exam
  origin at boot. Also added `chrome://*` and similar sensitive path blocklist entries.

### 4. `image/overlay/etc/systemd/system/examos-kiosk.service`
- BEFORE SHA-256: `BDC362835D92104B902F42E6BA1F0ED0F3E55782BF5B341B1BA55B42761A3316`
- AFTER  SHA-256: `2EE5613501291F15F47F0575C794E1EAAD01243CF2154544A5C56C2B6B7B95BE`
- Change: added `Requires=examos-chromium-policy.service` and
  `After=examos-chromium-policy.service` so the kiosk cannot start before the policy generator
  has successfully written a valid policy. If EXAM_URL is NOT_CONFIGURED, the generator fails,
  the kiosk does not start — fail-closed.

### 5. `image/scripts/generate-chromium-policy.sh` (NEW)
- SHA-256: `8DA91433DE629B030BFD630E8D092A9DDA8C6556BA1BE14F66C9EFBBD793DE85`
- Modeled on `generate-nftables.sh`. Reads /etc/examos/exam.conf, validates EXAM_URL:
  - Rejects NOT_CONFIGURED and empty (exit 1)
  - Requires https:// for non-loopback hosts (exit 1)
  - Rejects placeholder/documentation values
  - Extracts scheme+host[:port] as the allowed origin
  - Derives wildcard subdomain variant for non-IP hosts
  - Builds a complete Chromium managed-policy JSON with URLAllowlist /
    VideoCaptureAllowedUrls / AudioCaptureAllowedUrls set to exam origin + loopback
  - Python-validates the generated JSON before writing
  - Atomically writes (tmp + mv) to both policy paths
  - Options: --dry-run (print JSON, do not install), --check-only (validate only)
  - All log/warn messages go to stderr; only JSON goes to stdout on --dry-run
  - Exit codes: 0 success, 1 config error, 2 tool/write error

### 6. `image/overlay/etc/systemd/system/examos-chromium-policy.service` (NEW)
- SHA-256: `54D4CFE3E47B0B20776BA583C798B63BBEDDBA8C8271C13C9A26E1ECF927CC8F`
- Root oneshot, RemainAfterExit=yes, Before=examos-kiosk.service,
  After=local-fs.target examos-unseal.service, OnFailure=examos-lockdown-failed.target.
  Runs /usr/local/sbin/generate-chromium-policy.sh. Sandboxed: ProtectSystem=full,
  ProtectHome, PrivateTmp, NoNewPrivileges, no capabilities, ReadWritePaths limited to
  the two policy dirs, ReadOnlyPaths=/etc/examos/exam.conf.

---

## Verification results (all 11 checks, WSL Ubuntu-26.04, bash + python3)

| # | Check | Result |
|---|-------|--------|
| 1 | bash -n generate-chromium-policy.sh | PASS |
| 2 | bash -n generate-nftables.sh (regression) | PASS |
| 3 | JSON: chromium policy — no hardcoded domain, localhost present | PASS |
| 4 | JSON: opt/chrome policy — no catch-all https://* or hardcoded domain | PASS |
| 5 | exam.conf EXAM_URL=NOT_CONFIGURED (fail-closed) | PASS |
| 6 | kiosk.service Requires+After examos-chromium-policy.service | PASS |
| 7 | examos-chromium-policy.service file exists | PASS |
| 8 | generate-chromium-policy.sh source file exists | PASS |
| 9 | Dry-run with https://exam.example-university.edu — origin injected correctly | PASS |
| 10 | Generator rejects NOT_CONFIGURED (exit non-zero) | PASS |
| 11 | Generator rejects http:// non-loopback (exit non-zero) | PASS |

Verification commands:
```
wsl -d Ubuntu-26.04 -- bash \
  "/mnt/d/SEB BRO/artifacts/evidence/stage0-inspect-20261017-215333/stage1-verify.sh"
```
Exit code: 0

---

## What this does NOT fix (remaining gaps, not regressed)

- The launcher's `remove_directory_recursive` uses `system("rm -rf …")` — shell-injection surface
  if the `mkdtemp`-derived path were attacker-influenced. Tracked; safe to address in a later
  stage (path is mkdtemp, not user-supplied, so exploitability is low).
- `config_manager.c` still accepts `http://` for EXAM_URL (no HTTPS enforcement server-side).
  The generator enforces HTTPS at policy-generation time; server-side enforcement is a separate,
  later fix.
- `policy_signature` stored but never verified — separate Module C/D gap.
- In-memory exam submissions, no RBAC, no MFA, no tenant isolation — all tracked, not regressed.

---

## What must remain blocked

All phase gates (P0–P6) remain in their prior state (BLOCKED/FAIL/NOT_RUN/INVALIDATED).
This stage made OS-overlay source edits only; no image was built, no QEMU/hardware boot
was run, and no gate evidence was generated or overwritten.

---

## Before-state recovery

To restore exact pre-edit state, copy from:
  `D:\SEB BRO-stage1-backup-20261017-222900\`
SHA-256 manifest: `artifacts/evidence/stage0-inspect-20261017-215333/stage1-pre-edit-manifest.txt`
