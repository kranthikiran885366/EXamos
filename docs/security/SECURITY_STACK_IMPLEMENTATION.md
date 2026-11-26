# Security stack implementation and evidence

This change builds on ExamOS main commit `960fa01baa9d88672599e9a4d7510e222fb2006b`.
It does not approve ExamOS for live examinations or replace the existing release
gates. Source implementation, software test evidence and hardware qualification
are different states. The changes below must not be marketed as tamper-proof,
formally verified, certified, or an end-to-end post-quantum system.

## Implemented changes

| Area | Code delivered | Evidence and remaining boundary |
| --- | --- | --- |
| Existing trust path | Copies PostgreSQL result values before freeing them; selects the actual attestation ID; rejects transport identifiers that could break JSON; refuses success if RNG or transport persistence fails | Real libpq result objects and OpenSSL RSA wrapping exercised under AddressSanitizer/UBSan with database/TPM fixtures. No physical TPM key-unwrapping evidence. |
| Appliance identity | Removes the environment-only appliance-emulation bypass; missing kernel-lockdown evidence now rejects the appliance | Backend and agent compile. A real image still needs boot qualification. |
| Post-quantum release signatures | Adds `ml-dsa-65` to the existing fingerprint-bound, exact-manifest-byte release verifier | Real OpenSSL ML-DSA-65 signing/verification, altered-message, invalid-signature and wrong-metadata rejection. Other existing algorithms remain available; this is not mandatory hybrid signing. |
| Post-quantum key establishment | Adds OpenSSL ML-KEM-768 encapsulation/decapsulation primitives under `common/` | Real key generation, roundtrip, implicit rejection, malformed ciphertext length and wrong-key-type tests. These primitives are **not** enrolled TPM recipients or a deployed exam transport protocol. |
| Rust runtime guard | Adds a dependency-free, safe-Rust watchdog for Secure Boot, setup mode, root-mount-bound dm-verity, confidentiality lockdown, translated IOMMU groups, disabled swap, IMA executable-measurement rules and fresh Keylime decisions | Positive/negative filesystem fixtures. No physical DMA or measured-boot qualification. Missing controls prevent measured-profile kiosk startup; subsequent failure stops the kiosk through systemd. |
| Keylime integration | Queries an enrolled device's Keylime v2.5 verifier over CA-validated mTLS; requires measured-boot reference state, runtime policy, periodic-check state, PASS and fresh timestamps | Real local mTLS transport tests plus explicit decision fixtures. A real Keylime agent, verifier, runtime allowlist and measured-boot policy must be provisioned separately. No verifier-success cache or TLS bypass. |
| BPF-LSM | Adds global appliance policies denying ptrace and `mprotect` requesting simultaneous write+execute; a holder service sends READY only after both policies attach | Native loader and BPF bytecode compile with warnings as errors. Kernel verifier acceptance and Chromium compatibility are **not tested**. This supplements existing AppArmor/nftables/USBGuard; it is not a complete process/file/network policy engine. |
| A/B image/update integration | Adds two root slots and two verity slots to a new mkosi profile; ordered systemd-sysupdate transfers write the UKI last; UKIs get three boot attempts; successful-boot dependencies include trust and kiosk readiness | Configuration integration only. An image build, boot, interrupted-install test and failed-boot fallback test are required. Existing release/signature approval requirements remain in force. No update timer is enabled. |
| Runtime secret revocation | Stops key-holding services on trust failure; overwrites and unlinks bounded runtime secret files on lifecycle stop | Tests verify an already-open inode contains zeroes, and symlink/hardlink targets are rejected. This does **not** guarantee physical RAM zeroization or power-loss erasure. |

## Build profiles

The default `standard` profile retains the current image pipeline and receives
the trust-path and shared identity fixes. New privileged policies require an
explicit profile selection so an unqualified kernel is not silently deployed.

`EXAMOS_SECURITY_PROFILE=measured bash scripts/build-full-image.sh` builds and
stages the Rust guard, BPF-LSM policy, IMA rules, Keylime decision client and
secret-lifecycle units using the existing builder. Build-host dependencies add
Rust, Clang, libbpf and libelf development packages. The builder adds the image's
libbpf runtime dependency. The signed kernel command line enables translated,
strict IOMMU operation and the BPF LSM. A kernel must actually support these
features: command-line flags alone never satisfy the watchdog.

`EXAMOS_SECURITY_PROFILE=measured-ab` additionally requires:

| Variable | Required input |
| --- | --- |
| `EXAMOS_IMAGE_VERSION` | Monotonically increasing integer, 1–999999999 |
| `EXAMOS_SECURE_BOOT_KEY` | Authority-controlled Secure Boot signing-key path |
| `EXAMOS_SECURE_BOOT_CERT` | Corresponding enrolled Secure Boot certificate path |

The A/B layout targets x86-64 and reserves 1 GiB ESP, two 8 GiB root partitions
and two 128 MiB verity partitions. Qualify capacity and hardware before using
it. The image's `IMAGE_VERSION` supplies sysupdate's running-version protection.
Root and hash artifacts must use their actual repart-generated UUIDs in update
filenames. A new signed UKI must contain the matching verity root hash.

The transfer configuration reads a local source directory selected with
systemd-sysupdate's `--transfer-source=` option (systemd 257+). This supports
local artifact transport; it does **not** grant release approval, make a
fully air-gapped examination workflow, or implement smartcard authentication.
Do not install artifacts until the existing release gates approve them. There
is no automatic installer or new API that bypasses those gates in this change.

## Deployment provisioning

Do not bake shared credentials into a reusable image. Provision a real Keylime
agent and enroll it against the approved runtime and measured-boot policies.
Allow only the required verifier endpoints through the existing firewall.
Provision `/etc/examos/keylime-gate.json` as a root-owned regular file that is
not group/world writable, containing exactly these fields:

| Field | Meaning |
| --- | --- |
| `verifier_url` | HTTPS verifier origin, without credentials/path/query |
| `agent_uuid` | This appliance's actual enrolled Keylime UUID |
| `ca_certificate` | Absolute path to the trusted verifier CA bundle |
| `client_certificate` | Absolute path to this client's mTLS certificate |
| `client_key` | Absolute path to its private key, mode 0600 or stricter |
| `max_age_seconds` | Integer freshness limit from 1 to 60 seconds |

Certificate files must also be root-owned, regular and non-writable by other
users. A missing enrollment or stale verifier decision blocks the measured
profile. The local decision client is not a replacement for Keylime's TPM
quote checking, event-log replay or IMA allowlist verification. The configured
UUID must be bound to this appliance by the provisioning authority.
Initial startup permits two bounded retries while waiting for an authenticated
decision; it never admits the kiosk during that wait. Runtime trust failures
have no retry grace period. Synchronize the appliance and verifier clocks.

The BPF policy applies to the entire dedicated appliance and deliberately
rejects ptrace even by ordinary root processes. Test Chromium, crash handling
and maintenance workflows on the declared kernel before deployment. Firmware
must expose working IOMMU groups, and every inspected group must use a
translated DMA domain. This does not establish pre-OS DMA isolation or correct
firmware behavior.

## Software validation

Run `make test-security-stack` on a build host with OpenSSL 3.5+ and the
dependencies above. `.github/workflows/security-stack.yml` runs this in Debian
Trixie. The suite includes real ML-KEM/ML-DSA operations, the existing classical
release-signature regressions, AddressSanitizer/UBSan transport regressions,
two Rust tests, eight Python tests, BPF compilation and shell syntax checks.
The local sandbox required `ASAN_OPTIONS=detect_leaks=0` because LeakSanitizer
cannot operate under its process tracing; address/undefined checks still ran.
Native backend, migration/provisioning binaries and the existing agent also
built locally. CI and physical hardware results must be recorded separately.

## Requirements that remain unimplemented or externally blocked

| Requirement | What is still required |
| --- | --- |
| seL4 separation kernel | A distinct platform port and threat model, device support, virtualization boundaries and proof-scope review. The existing Linux/Cage product is not converted to seL4. |
| NIST SP 800-193 firmware resilience | OEM/platform support for firmware protection, authenticated recovery, protected roots of trust and actual recovery tests. An OS flag cannot implement these firmware capabilities. |
| SELinux MLS | Classification model, a separate SELinux-enabled image policy, labeled storage, application integration and information-flow tests. Existing AppArmor is retained. |
| Complete DMA protection | Physical PCIe/Thunderbolt testing, firmware and pre-boot validation, interrupt-remapping evidence and hardware qualification. |
| Tamper hardware / physical RAM zeroization | Actual chassis/tamper sensors and platform-supported memory/key destruction. Software cannot execute a RAM wipe after unexpected loss of power. |
| BadUSB behavioral AI | Consented labeled data, an evaluated model, latency/error budgets and integration with existing USBGuard. No fabricated detector is added. |
| Fully air-gapped exams / smartcards | Offline trust freshness/revocation design, answer/evidence transfer and recovery, actual token integration and acceptance tests. Local A/B artifact transfer is only one component. |
| End-to-end post-quantum protection | Authenticated ML-KEM recipient enrollment, context-bound transport, AEAD, hybrid migration policy, TLS/provider deployment, key custody and interoperability tests. Standard TPM quotes and UEFI Secure Boot are still classical. |
| Common Criteria / IC3S | Security target, TOE boundary, assurance evidence, independent lab evaluation and a certificate issued by the scheme. Code changes do not issue a certificate. |
| Live exam release | Resolve existing policy-publication/device-acknowledgement and phase-gate blockers, then qualify the exact image on physical devices. No release gate is marked PASS by this change. |

## Primary integration references

- https://docs.kernel.org/admin-guide/device-mapper/verity.html
- https://docs.kernel.org/bpf/prog_lsm.html
- https://keylime-docs.readthedocs.io/en/latest/rest_apis/2_5/verifier.html
- https://github.com/keylime/keylime/blob/master/keylime/common/states.py
- https://docs.openssl.org/3.5/man7/EVP_SIGNATURE-ML-DSA/
- https://docs.openssl.org/3.5/man7/EVP_KEM-ML-KEM/
- https://www.freedesktop.org/software/systemd/man/257/sysupdate.d.html
- https://systemd.io/AUTOMATIC_BOOT_ASSESSMENT/
