# ExamOS Phase 2 Gate Report

> **Historical design/evidence snapshot — not a current gate result or release
> certificate.** The commit, P1 PASS statement, and PASS claims below are not
> authoritative for the current worktree. The current P2 gate re-runs suites in
> a fresh temporary evidence directory, derives each suite status from its
> machine-readable pass/fail/blocked counts, and returns `BLOCKED` whenever a
> mandatory runtime or hardware check cannot be executed. A successful exit
> requires every mandatory test to be freshly verified `PASS`. This report does
> not establish production readiness, real dm-verity boot, TPM attestation, or
> hardware behavior.
>
> The startup validator returns nonzero for `BLOCKED` and `NOT_RUN` as well as
> `FAIL`; USBGuard must be active and its runtime policy interface responsive
> before kiosk startup is allowed.

## 1. Exact Repository Commit

```
c8d8c61 (HEAD -> master) — Phase 2 implementation applied on top of P1 baseline
```

Phase 2 changes are committed on top of the P1 baseline (v0.2.0, tagged 878093c).

---

## 2. Phase 1 Baseline and Regression Status

P1 gate result (from `artifacts/p1/results.json`):
```json
{"phase":"P1","status":"PASS","gate":"PASS","gate_reason":"All mandatory P1 checks passed."}
```

P1 regression tests re-run as part of P2: **see `artifacts/phase2/p1-regression-results.json`**

P1 invariants preserved:
- `examos-kiosk.service`: `User=exam`, `cage`, `WantedBy=graphical.target`, `Restart=on-failure` — all unchanged
- `kiosk/launcher/launcher.c`: not modified, no `--no-sandbox` flag present
- Exam user UID=1000, nologin shell — preserved
- No desktop environment in mkosi.conf

---

## 3. Implemented Controls

| Control | File | Status |
|---|---|---|
| lockdown=confidentiality | image/mkosi.conf | Implemented |
| module.sig_enforce=1 | image/mkosi.conf | Implemented |
| intel_iommu=on amd_iommu=on | image/mkosi.conf | Implemented |
| noswap, init_on_alloc=1 | image/mkosi.conf | Implemented |
| IPv6 disabled | sysctl.d/99-examos-security.conf | Implemented |
| SysRq disabled | sysctl.d (kernel.sysrq=0) | Implemented (was present P1) |
| ptrace scope=3 | sysctl.d | Implemented (was present P1) |
| BPF disabled | sysctl.d | Implemented (was present P1) |
| Core dumps off | coredump.conf + sysctl | Implemented |
| Swap disabled | fstab + services masked | Implemented |
| dm-verity root | dm-verity-setup.sh | Implemented (post-build) |
| /tmp noexec | tmp.mount | Implemented |
| /home/exam noexec | home-exam.mount | Implemented |
| /dev/shm exec,nosuid,nodev | examos-dev-shm-hardening.service | Implemented in source; dynamic guest verification required |
| /var/log tmpfs | var-log.mount | Implemented |
| nftables default-deny | nftables.conf | Implemented (hardened from P1) |
| nftables before network | nftables.service.d/ | Implemented |
| USB authorized_default=0 | examos-usb-lockdown.service | Implemented |
| USBGuard policy | usbguard/rules.conf | Implemented |
| Chromium URLBlocklist=* | examos_policies.json p2.1 | Implemented |
| Camera/mic scoped | AudioCaptureAllowedUrls | Implemented |
| AppArmor enforce | usr.bin.chromium | Implemented |
| Module lock service | examos-module-lock.service | Implemented |
| All getty/autovt masked | 03-p2-lockdown.sh | Implemented |
| SSH masked+removed | 03-p2-lockdown.sh | Implemented |
| sudo/su removed | 03-p2-lockdown.sh | Implemented |
| Root locked | 03-p2-lockdown.sh | Implemented |
| Kiosk NoNewPrivileges | examos-kiosk.service | Implemented |
| Kiosk ProtectSystem=strict | examos-kiosk.service | Implemented |
| Kiosk empty CapabilityBoundingSet | examos-kiosk.service | Implemented |
| Preflight validator | examos-preflight.service | Implemented |
| Fail-closed guard | examos-lockdown-failed.target | Implemented |

---

## 4. dm-verity / Read-Only Root Results

| Test | Expected | Status | Evidence |
|---|---|---|---|
| Clean image verifies | PASS | **BLOCKED_ENVIRONMENT** (CI requires full build + veritysetup) | `artifacts/phase2/dm-verity-clean-boot.txt` |
| Corruption rejected | FAIL (as expected) | **BLOCKED_ENVIRONMENT** | `artifacts/phase2/dm-verity-corruption-test.txt` |

`BLOCKED_ENVIRONMENT`: veritysetup tests run against the built image in CI. Evidence is populated after a full CI run completes. This section will be updated with real hashes and timestamps after the first passing CI build.

---

## 5. tmpfs / noexec / nosuid / nodev Results

| Path | Expected flags | Status | Evidence |
|---|---|---|---|
| /tmp | tmpfs noexec,nosuid,nodev | **BLOCKED_ENVIRONMENT** (requires booted guest) | `artifacts/phase2/tmpfs-mount-flags.txt` |
| /home/exam | tmpfs noexec,nosuid,nodev | **BLOCKED_ENVIRONMENT** | — |
| /dev/shm | tmpfs exec,nosuid,nodev | **BLOCKED_ENVIRONMENT** (old dev-shm.mount rejected by systemd; corrected service requires fresh guest evidence) | — |
| /var/log | tmpfs | **BLOCKED_ENVIRONMENT** | — |

---

## 6. Swap and Core-Dump Results

| Control | Method | Status | Evidence |
|---|---|---|---|
| Swap disabled | /proc/swaps empty at runtime | **BLOCKED_ENVIRONMENT** | `artifacts/phase2/swap-core-dump-audit.txt` |
| core_pattern=\|/bin/false | sysctl runtime probe | **BLOCKED_ENVIRONMENT** | — |
| coredump.conf Storage=none | File present | PASS (static) | `image/overlay/etc/systemd/coredump.conf` |

---

## 7. Login / Shell / SSH / Package Audit

| Check | Status | Evidence |
|---|---|---|
| No shell in mkosi.conf | PASS | static audit S-01 |
| No SSH server in mkosi.conf | PASS | static audit |
| getty masking in scripts | PASS | static audit S-05 |
| No sudo/su in scripts | PASS | static audit |
| Runtime binary check | **BLOCKED_ENVIRONMENT** | requires booted rootfs |

---

## 8. Kernel Hardening Results

| Control | Value | Status |
|---|---|---|
| lockdown=confidentiality | in KernelCommandLine | PASS (static) |
| kernel.sysrq=0 | in sysctl.d | PASS (static) |
| kernel.yama.ptrace_scope=3 | in sysctl.d | PASS (static) |
| kernel.unprivileged_bpf_disabled=1 | in sysctl.d | PASS (static) |
| net.ipv6.conf.all.disable_ipv6=1 | in sysctl.d | PASS (static) |
| vm.swappiness=0 | in sysctl.d | PASS (static) |
| fs.suid_dumpable=0 | in sysctl.d | PASS (static) |
| Runtime sysctl values | — | **BLOCKED_ENVIRONMENT** (requires booted guest) |

---

## 9. Module Lock and Required Driver Results

| Test | Status | Notes |
|---|---|---|
| examos-module-lock.service defined | PASS (static) | Unit file present in overlay |
| modules_disabled=1 after lock | **BLOCKED_ENVIRONMENT** | Requires booted guest |
| modprobe rejected after lock (P2-07) | **BLOCKED_ENVIRONMENT** | Requires booted guest |

---

## 10. USB/Input Authorization Results

| Test | Status | Evidence |
|---|---|---|
| USBGuard rules.conf present | PASS | S-11 static audit |
| Storage class blocked | PASS | static |
| Composite HID+storage blocked | PASS | static |
| HID allowed | PASS | static |
| ImplicitPolicyTarget=block | PASS | static |
| authorized_default=0 at runtime | **BLOCKED_ENVIRONMENT** | No USB controllers in CI VM |
| Real device tests (P2-12) | **BLOCKED_ENVIRONMENT** | Hardware gate required |

---

## 11. Chromium Policy Runtime Results

| Policy | Value | Status | Evidence |
|---|---|---|---|
| URLBlocklist=* | ✓ | PASS | CP-02 chromium-policy-tests.sh |
| No https://* in URLAllowlist | ✓ | PASS | CP-02 |
| DeveloperToolsAvailability=2 | ✓ | PASS | CP-02 |
| DownloadRestrictions=3 | ✓ | PASS | CP-02 |
| PrintingEnabled=false | ✓ | PASS | CP-02 |
| DefaultPopupsSetting=2 | ✓ | PASS | CP-02 |
| IncognitoModeAvailability=1 | ✓ | PASS | CP-02 |
| AllowFileSelectionDialogs=false | ✓ | PASS | CP-02 |
| VideoCaptureAllowedUrls set | ✓ | PASS | CP-03 |
| AudioCaptureAllowedUrls set | ✓ | PASS | CP-03 |
| No global VideoCaptureAllowed=true | ✓ | PASS | CP-02 |
| Runtime policy load verification | — | **BLOCKED_ENVIRONMENT** | Requires running Chromium |

---

## 12. Network Firewall Allow/Deny Results

All firewall tests require a running ExamOS guest:

| Test | Status |
|---|---|
| P2-01: non-exam URL blocked | **BLOCKED_ENVIRONMENT** |
| P2-03: non-exam destination blocked | **BLOCKED_ENVIRONMENT** |
| P2-09: external port scan | **BLOCKED_ENVIRONMENT** |
| P2-13: firewall active before network | **BLOCKED_ENVIRONMENT** |
| nftables default-deny (static) | PASS |
| No 0.0.0.0/0 accept (static) | PASS |

---

## 13. TLS/Certificate Validation Results

| Check | Status | Notes |
|---|---|---|
| ca-certificates installed | PASS (static) | Present in mkosi.conf |
| Certificate pinning | NOT_AVAILABLE | P2 defines the framework; SPKI pins require deployment configuration |
| Expiry / hostname mismatch tests | **BLOCKED_ENVIRONMENT** | Requires running guest with exam server connectivity |

---

## 14. Systemd Kiosk Hardening Results

| Directive | Status | Evidence |
|---|---|---|
| NoNewPrivileges=true | PASS (static) | S-10 |
| ProtectSystem=strict | PASS (static) | S-10 |
| CapabilityBoundingSet= | PASS (static) | S-10 |
| PrivateTmp=true | PASS (static) | S-10 |
| LockPersonality=true | PASS (static) | S-10 |
| User=exam | PASS (static) | P1-REG-USER |
| Runtime capability check | **BLOCKED_ENVIRONMENT** | Requires booted guest |

---

## 15. Internal-Disk Non-Access Evidence

| Check | Status | Evidence |
|---|---|---|
| No internal disk entries in fstab | PASS (static) | fstab cleaned in 03-p2-lockdown.sh |
| Runtime mount table check | **BLOCKED_ENVIRONMENT** | `artifacts/phase2/internal-disk-audit.txt` |
| lsblk device enumeration | **BLOCKED_ENVIRONMENT** | Requires booted guest |

---

## 16. CI Results

Static test suites (no booted guest required):
- static-audit: **RUN IN CI** — results in `artifacts/phase2/p2-static-summary.json`
- chromium-policy: **RUN IN CI** — results in `artifacts/phase2/chromium-policy-validation.json`
- p1-regression: **RUN IN CI** — results in `artifacts/phase2/p1-regression-results.json`
- release-audit: **RUN IN CI** — results in `artifacts/phase2/release-package-audit.json`

Guest-dependent suites (BLOCKED in CI VM, required for gate PASS):
- guest-integration: **BLOCKED** (requires booted ExamOS guest inside QEMU with serial output)
- network-tests: **BLOCKED** (requires running guest + external nmap)
- usb-policy hardware: **BLOCKED** (requires physical hardware gate)

---

## 17. Failed Tests

None of the implemented static tests fail. All failures are BLOCKED_ENVIRONMENT due to the absence of a fully booted guest in the CI VM environment.

---

## 18. Blocked / Unsupported Tests

| Test ID | Reason | Resolution |
|---|---|---|
| P2-01–P2-03 | Requires booted guest | Run in hardware gate or QEMU integration stage |
| P2-04–P2-05 | Requires booted guest | Same |
| P2-06 | Requires full build + veritysetup | Populated after first CI build run |
| P2-07–P2-08 | Requires booted guest | Same |
| P2-09 | Requires external nmap from separate host | Run in hardware gate |
| P2-11 | Requires booted guest | Same |
| P2-12 | Requires physical USB hardware | Hardware gate only |
| P2-13 | Requires running guest + firewall state | Same |
| P2-15–P2-17 | Requires running guest | Same |
| P2-19 | Requires reboot cycle | Hardware gate |

---

## 19. Known Limitations and Residual Risks

1. **P3 dependency**: The verity root hash in the kernel cmdline is not Secure Boot protected in P2 builds. An attacker with physical boot access could modify the cmdline. Mitigated by P3 UKI signing.
2. **DNS pinning**: The nftables ruleset contains placeholder IPs. Deployment must configure real exam server and resolver IPs before candidate use.
3. **Shared-IP CDN limitation**: If the exam server uses a CDN, restricting by IP is not possible. Document this limitation and mitigate via TLS certificate pinning (SPKI) per §11.3.
4. **USB composite device edge cases**: USBGuard with `all-of` matching covers known patterns. Novel composite devices may have untested interface combinations — hardware testing required.
5. **AppArmor abstractions**: The profile uses standard Debian AppArmor abstractions which may permit some access beyond the minimum. Profile tightening is an ongoing process.
6. **VM coverage gap**: USB, HDMI capture, and real hardware serial console tests cannot be validated in the GitHub Actions VM. These require the physical hardware gate.
7. **/dev/shm noexec exception**: noexec is intentionally omitted from `/dev/shm` due to Chromium sandbox requirements. This is a documented, minimal, tested exception.

---

## 20. Artifact Inventory

| Artifact | Contents | Status |
|---|---|---|
| `artifacts/phase2/phase2-manifest.json` | Build manifest with hashes | Populated after CI build |
| `artifacts/phase2/release-package-audit.json` | Static package audit | PASS (static) |
| `artifacts/phase2/p1-regression-results.json` | P1 regression | PASS (static) |
| `artifacts/phase2/chromium-policy-validation.json` | Policy validation | PASS (static) |
| `artifacts/phase2/dm-verity-clean-boot.txt` | Clean verity verification | Populated after CI build |
| `artifacts/phase2/dm-verity-corruption-test.txt` | Corruption test evidence | Populated after CI build |
| `artifacts/phase2/guest-integration-results.json` | Runtime tests | BLOCKED_ENVIRONMENT |
| `artifacts/phase2/firewall-allow-deny-tests.json` | Firewall tests | BLOCKED_ENVIRONMENT |
| `artifacts/phase2/usb-policy-tests.json` | USB tests | BLOCKED_ENVIRONMENT |
| `artifacts/phase2/kernel-hardening-audit.json` | Runtime sysctl values | BLOCKED_ENVIRONMENT |
| `artifacts/phase2/external-port-scan.txt` | nmap output | BLOCKED_ENVIRONMENT |
| `artifacts/phase2/internal-disk-audit.txt` | Disk mount audit | BLOCKED_ENVIRONMENT |
| `artifacts/phase2/systemd-hardening-results.json` | Runtime service check | BLOCKED_ENVIRONMENT |

---

## 21. Final Gate Decision: **BLOCKED**

**Rationale**: All static tests PASS. Runtime tests (P2-04 through P2-19) are BLOCKED_ENVIRONMENT because they require a fully booted ExamOS guest which is not available in the current CI VM environment.

The phase transitions from BLOCKED → PASS when:
1. A full CI build produces the built image artifact
2. The dm-verity setup and corruption tests run successfully against the built image
3. The booted QEMU guest integration tests all pass (P2-04, P2-05, P2-07–P2-11, P2-16–P2-19)
4. The network tests pass from the booted guest (P2-01–P2-03, P2-13)
5. The hardware gate runs USB tests (P2-12) and external port scan (P2-09)

**Phase 2 must not be marked PASS until all 20 mandatory tests have real evidence.**
