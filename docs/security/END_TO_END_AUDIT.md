# ExamOS end-to-end production-readiness audit

**Audit snapshot:** 2026-10-12 (reconciled after P0 KVM validation)
**HEAD:** `c8d8c6149458e9c1611966d5f2db66ed2f42e2d1`
**Branch at snapshot:** `work/p0-secure-release-remediation-20261011`
**Decision: BLOCKED — NOT APPROVED FOR LIVE EXAMINATIONS**

The current worktree is modified; the exact dirty-path count is regenerated
by each P0 gate run. On 2026-10-12, a raw image passed QEMU/OVMF disk boot
under KVM with readiness-driven shutdown and passed snapshot-isolated
first-boot account/login checks, but those recorded tests bind to an older
image digest than the current disk build. The server passed a temporary
warning-as-error build plus the malformed-AK-name command-injection
regression. These checks do not make the tree release-ready. The Windows read-only hardware
preflight identified the Dell model and disk inventory, but privilege denied
Secure Boot, TPM, and BitLocker status. No physical-device writes or boot were
performed. This remains a repository evidence review, not a third-party
penetration test or formal verification of every source file.

## Executive decision

ExamOS has meaningful prototype components: a Linux image configuration,
Chromium/Cage kiosk, native C/C++ services, TPM quote parsing/signature
verification code, file-backed integrity journals, and phase test suites.
These facts do not establish a production examination appliance. The
release-blocking evidence is explicit:

1. The historical A-11 shell-injection defect is fixed in the current C
   service: MakeCredential runs with fixed argv, AK Names receive full grammar
   validation, and the server regression rejected a crafted name without
   executing its marker command. Physical TPM credential activation remains
   unverified.
2. P1 is recorded `FAIL`; P2 records 20 mandatory tests as `NOT_RUN`.
3. The aggregate P3 result is explicitly `INVALIDATED`; the separate 18/18
   `swtpm` suite artifact is a dirty-tree development result, not physical-TPM
   or release evidence.
4. P4's previous detection-quality PASS is explicitly invalidated. The
   optional OpenCV code is not enabled or linked by the current proctor
   Makefile, no model package is installed in the image, and no valid
   labelled evaluation dataset is supplied.
5. P5 is `BLOCKED`: the viva provider is unavailable and dependent review,
   privacy/duplicate-response, and regression gates are blocked.
6. The P6 prerequisite report blocks release for phase evidence, hardware
   diversity, authorized red-team execution, pilot evidence, production key
   custody, real P4 data, and P5 provider availability.

No current evidence supports a production-readiness claim. The current disk
image digest is `c0b4619a7e1f3fb72cff284c493dd8988074bc61113926d29fead480997b00af`;
the recorded disk boot and first-boot results use the older digest
`a531ad41eeb3a1cb8a01a714a7c0af625acd3aca4264ad43be30f26a1361de3f`.
The current ISO digest is `64fe70b0cce8c68834de0c6a73e9dbeb0f1e2fa3b09a22f5b231c791aba1eae7`;
its QEMU UEFI optical boot failed with exit 139 before required readiness
markers. VMware Workstation boot evidence is also outstanding.

## Phase-by-phase evidence and production exit criteria

| Phase | Current repository evidence | Blockers | Minimum production exit criteria |
|---|---|---|---|
| **P0 — build and boot** | Current disk build digest `c0b4619a…997b00af` is recorded. Disk boot and first-boot PASS records bind to older digest `a531ad41…1361de3f`. The current ISO digest `64fe70b0…1eae7` has a failed optical boot (exit 139). | Current tree remains dirty; no current-image disk boot/first-boot pass, no optical boot pass, no VMware boot, complete kiosk flow, or physical device diversity is proven. The P0 guest targets x86-64 only; no physical model is production-qualified. | Build from a clean immutable commit in CI; record toolchain, dependencies, image/UKI/rootfs digests and SBOM; reproduce the build; prove signed boot chain and positive/negative boot cases; boot into the locked kiosk; qualify each declared device/platform separately. |
| **P1 — kiosk and network** | `artifacts/p1/results.json` is `FAIL`: `artifact_exists` and `guest_boot` fail; `exam_url` and `performance` are BLOCKED. Some configuration checks pass. | No successful P1 acceptance result and no demonstrated boot-to-locked-exam flow on supported hardware. | Pass the full P1 gate on a clean image; boot into the exam URL without an alternate desktop/shell; test recovery and process restart; verify network allow/deny and supported-device performance on the declared matrix. |
| **P2 — OS lockdown** | `artifacts/phase2/phase2-manifest.json` explicitly says `NOT_RUN`, with 20 mandatory tests not run and CI placeholder values. Static configuration exists in `image/overlay/`, including nftables, AppArmor, USBGuard and systemd hardening. | No live firewall, dm-verity corruption, Secure Boot, USB authorization, kernel-lock, Chromium policy, or guest integration evidence. `deployment.conf` and firewall inputs intentionally contain deployment-required values. | Generate the appliance configuration from approved deployment data; run every mandatory gate in a booted guest and on required hardware; test adversarial negative cases (USB, network, tampering, policy bypass, recovery); verify fail-closed startup and bind all results to the release commit/image digests. |
| **P3 — attestation and key release** | `artifacts/p3/results.json` explicitly marks aggregate P3 `INVALIDATED` because its source tree was dirty and a later fresh run aborted at P3-014. A separate `swtpm` suite artifact records development-only outcomes. The C service has a TPMS_ATTEST parser and AK-signature verification path; the Go verifier is development-only. A-11 has a fixed-argv implementation and passed a malformed-name command-execution regression in the temporary server smoke run. A-13's unsafe non-loopback override is removed; a regression is included in the server smoke. `tests/p3/release-gate.py` requires physical TPM quote, EK chain, credential activation, event-log replay, Secure Boot, dm-verity rejection, runtime lockdown, key-release binding, reproducible build, digests and independent approval. | No aggregate release evidence; `swtpm` is not hardware. Signed production registries, key ceremony and physical TPM evidence are absent. There is still no verified remote TLS/mTLS deployment. | Use enrolled production device/release registries and real EK certificate chains; validate AK activation and signatures with hardware TPMs; implement/replay genuine TCG event logs; test replay, revocation, PCR mismatch, missing secrets and key release on hardware; deploy reviewed TLS/mTLS; complete independent signed release evidence and key ceremony. |
| **P4 — proctoring and event integrity** | `artifacts/phase4/phase4-manifest.json` says INVALIDATED: detection quality was based on fabricated data and P0–P3 regression failed. Event-chain/tamper and concurrency artifacts exist, but do not overturn this gate. The current `proctoring/analysis/vision_engine.cpp` can use OpenCV DNN models only under `EXAMOS_USE_OPENCV`; `proctoring/Makefile` neither defines/links OpenCV nor supplies model files, and `image/mkosi.conf` does not install OpenCV. | Prior metric tables are invalid, no valid real annotated dataset is present, and the current appliance build cannot load the optional model implementation. Detection, gaze and liveness performance are not certified. | Enable and package pinned, licensed models and their hashes; fail closed with explicit unavailable status; curate consented, representative, independently labelled evaluation data; report subgroup/error bounds and false-positive/negative rates; test adversarial video/device inputs, privacy/deletion/retention, load/backpressure and human escalation; rerun clean commit-bound P4 and P0–P3 regression gates. |
| **P5 — behavior, viva and human review** | `artifacts/phase5/manifest.json`: P5-A–E PASS in recorded tests; P5-F/G/H BLOCKED because the viva provider is unavailable (P5-H also records `mutation_rejected: false`); P5-I BLOCKED because fresh commit-bound P0–P4 evidence is absent. Test fixtures include synthetic behavior and development release/PCR data. | Provider, review, privacy/authorization and full-regression gates are not complete. Small synthetic results do not establish cheating detection accuracy or fairness. | Establish the production provider contract and outage behavior; test generated content, duplicate/mutated answers, authorization boundaries and data minimization; validate false flags and appeal/human-review workflows on independently labelled, representative data; obtain privacy/legal review; pass P5-I against fresh P0–P4 evidence. |
| **P6 — production prerequisites** | `tests/p6/prerequisite-audit.py` records BLOCKED and creates `docs/phase6/prerequisite-status.md`. It identifies evidence/architecture mismatch, three-model physical matrix, authorized red-team evidence, 10–20-person pilot, production key ceremony, real P4 dataset, and P5 provider prerequisites. | No production acceptance package. The audit's P0 evidence mapping looks for `artifacts/p0/results.json`, while current split P0 build/boot results exist; resolve the schema/mapping instead of interpreting missing aggregate as proof that no P0 work happened. The required Node/Mongo/Redis/Python/SFU/Docker architecture in that report does not match the current native-C design; product owner must explicitly accept or revise that requirement. | Resolve the architecture decision without silently replacing the frozen design; complete each prerequisite with named owners and approval; run an authorized red team and documented remediation/retest; pilot only with informed volunteers and a rollback plan; verify multi-model hardware, production key custody and an independently approved release package. |

## Confirmed source-level security and reliability findings

### A-11 — Shell command injection in credential challenge (FIXED; regression verified)

The historical root cause was shell construction with an agent-supplied TPM
Name and incomplete validation. The current service validates the full
`000b` + 64-hex grammar and invokes `tpm2_makecredential` through `fork` and
`execlp` argv, without a shell. A-11 also fixed challenge-ID truncation by
storing device-bound, expiring, single-use challenge records.

The 2026-10-12 regression used a temporary server build and a crafted
credential-challenge request containing a shell command marker. The route
rejected the malformed TPM Name (HTTP 500) and the marker file was not
created. The 2026-10-12 temporary server smoke passed 11/11 checks, including the
malformed-name injection regression and a non-loopback bind attempt with the
former TLS assertion enabled. No marker command ran. Production credential
activation on an enrolled physical TPM remains unverified.

### A-12 — model code is not in the release build path (HIGH for P4 claims)

The current vision source is better than the older documentation suggests: it
contains optional OpenCV face/object models and reports model unavailability
instead of fabricated detections. However, the current proctor Makefile does
not set `EXAMOS_USE_OPENCV` or link OpenCV, and the image package list does not
include OpenCV or model artifacts. Therefore source presence is not evidence
that the shipped image performs those detections. This reinforces, rather than
repairs, the invalidated P4 metric claim.

### A-13 — unverified TLS-proxy assertion could enable remote plaintext (FIXED; remote TLS remains outstanding)

The C server speaks plaintext HTTP. It now refuses every bind address except
`127.0.0.1`, even if `EXAMOS_TLS_TERMINATED=1` is set; the environment flag
cannot establish the presence of a hardened TLS/mTLS proxy. The server smoke
regression starts with the old bypass flag and a reserved non-local test
address, requiring refusal before bind. Remote access remains blocked until a
reviewed TLS/mTLS deployment and certificate lifecycle are implemented and
validated. Localhost HTTP itself is not end-to-end encrypted.

### A-14 — connection resource controls (FIXED; runtime regression verified)

The server still uses detached per-connection threads, but admission is now
bounded by `EXAMOS_MAX_ACTIVE_CONNECTIONS` (default 64, hard maximum 1024).
At capacity it returns HTTP 503, and the worker slot is released on thread
completion or creation failure. Socket receive/send deadlines are configured.
The 2026-10-11 live saturation/recovery regression verified overload responses
and capacity recovery. This closes the unbounded-thread-creation finding; it
does not replace broader production load testing.

## Production requirements common to all phases

- **Cryptographic trust and supply chain:** reproducible clean builds; pinned
  and reviewed dependencies; SBOM; image/UKI signing; release provenance;
  vulnerability scanning and patch/rollback process; independently held
  signing keys and documented rotation/revocation.
- **Identity and transport:** TLS for every remote hop; mutual or otherwise
  strong service authentication; least privilege and key rotation; candidate
  and administrator abuse controls, rate limits, audit trail and recovery.
- **Storage and recovery:** durable transactional storage for answers,
  sessions, attestation state and evidence; encryption and access control;
  integrity verification, backups and restore drills; tested power-loss and
  crash consistency; retention/deletion controls.
- **Operations and resilience:** bounded queues/threads, timeouts, health and
  readiness checks, monitored alerts, incident response, support and outage
  procedures, tested updates and rollback, capacity targets and availability
  SLOs.
- **Privacy, fairness and governance:** purpose limitation and informed
  consent; data minimization, retention and deletion; model/data provenance,
  bias and subgroup analysis; human review and candidate appeal; accessibility;
  applicable privacy, employment/assessment and education-law review.
- **Evidence quality:** each gate must have a defined owner, reproducible
  command, immutable output, source commit/image hash, environment details,
  complete positive and negative results, independent approval, and a rule
  that BLOCKED/NOT_RUN/INVALIDATED can never count as PASS.

## Recommended order of work

1. Keep remote binding disabled until the separate A-13 TLS/mTLS deployment
   is independently verified; A-11's code regression is verified but physical
   TPM activation remains outstanding.
2. Reconcile P0 evidence schema and rebuild/run P0–P2 from a clean commit;
   replace placeholder deployment values and obtain real guest/hardware
   evidence.
3. Complete the dedicated P3 release gate with physical TPM and production
   trust provisioning; do not treat the 18/18 swtpm run as release approval.
4. Rebuild P4 around an enabled, pinned model stack and real labelled data;
   then rerun P4 and regression tests.
5. Unblock P5-F/G/H, resolve P5-H mutation behavior, and validate privacy,
   error and human-review paths before a pilot.
6. Complete the P6 architecture decision, physical matrix, authorized
   red-team, pilot, key ceremony, operational readiness and independent
   release approval.

## TCS iON NQT comparison

The separate
[TCS iON NQT comparison](TCS_NQT_COMPARISON.md) compares ExamOS with what is
publicly verifiable about the TCS iON NQT product. It does not claim access to
TCS internal operating-system controls.

## Evidence references

- P0 split evidence: [`artifacts/p0/build-result.json`](../../artifacts/p0/build-result.json), [`artifacts/p0/boot-result.json`](../../artifacts/p0/boot-result.json), and the later [`P0 ISO build/boot evidence`](../../artifacts/evidence/p0-20261011T131622Z/).
- P1: [`artifacts/p1/results.json`](../../artifacts/p1/results.json).
- P2: [`artifacts/phase2/phase2-manifest.json`](../../artifacts/phase2/phase2-manifest.json).
- P3 aggregate result: [`artifacts/p3/results.json`](../../artifacts/p3/results.json) (INVALIDATED); separate suite record: [`artifacts/p3/attestation-suite-results.json`](../../artifacts/p3/attestation-suite-results.json); release acceptance criteria: [`tests/p3/release-gate.py`](../../tests/p3/release-gate.py).
- P4 invalidated result: [`artifacts/phase4/phase4-manifest.json`](../../artifacts/phase4/phase4-manifest.json).
- P5: [`artifacts/phase5/manifest.json`](../../artifacts/phase5/manifest.json).
- P6 prerequisite evaluator/report: [`tests/p6/prerequisite-audit.py`](../../tests/p6/prerequisite-audit.py) and [`docs/phase6/prerequisite-status.md`](../phase6/prerequisite-status.md).

These source artifacts are snapshots, not certification. Re-run and regenerate
the required gates after fixes on a clean, identified release commit.
