# ExamOS implementation plan

**Plan date:** 2026-10-17  
**Repository:** `work/p0-secure-release-remediation-20261011`  
**Classification:** development planning; not a production approval

## Goal

Deliver a secure examination appliance and managed service only after each
security, operational, privacy, and business claim has evidence appropriate
to that claim. Development and simulator results must remain distinct from
physical-device, production, and independent-assessment evidence.

The repository is currently a development prototype. The existing audit
records P1 as FAIL, P2 runtime tests as NOT_RUN, aggregate P3/P4 as INVALIDATED,
P5/P6 as BLOCKED, and production use as NOT APPROVED. These states are release
blockers and must not be silently promoted. See
[`END_TO_END_AUDIT.md`](security/END_TO_END_AUDIT.md),
[`IMPLEMENTATION_INVENTORY.md`](security/IMPLEMENTATION_INVENTORY.md),
[`ISSUE_REGISTER.md`](security/ISSUE_REGISTER.md), and
[`RELEASE_READINESS.md`](security/RELEASE_READINESS.md).

## Working rules

1. Preserve all existing source, artifacts, and evidence. Do not use `git
   clean`, `git reset`, bulk restore, or overwrite existing evidence.
2. Before editing a dirty tree, make a separate timestamped backup and record
   its SHA-256. A backup is a recovery aid, not a clean source baseline.
3. Every result records source revision and dirty state, exact artifact
   digests, tool/environment versions, command, and PASS/FAIL/BLOCKED/NOT_RUN.
4. Simulators, fixtures, and synthetic data are labelled as such. They cannot
   establish physical hardware behavior, model accuracy, or production trust.
5. Missing trust inputs fail closed. No test bypass may authorize a release.
6. No physical disk, firmware, Secure Boot key, TPM, or USB-media writes occur
   without an explicit device-specific authorization and recovery plan.
7. Run a test only when its prerequisites are met and its outputs can be kept
   separate from existing evidence. A failed or unavailable prerequisite is
   recorded as such, never counted as a pass.

## Baseline protection and current status

An external worktree snapshot was created before this plan was added:

- Archive: `D:\SEB BRO-backup-20261017-200057.zip`
- Included existing files: 661
- Archive size: 20,369,656 bytes
- SHA-256: `E2474E4AAB17AEC87D5AA269CC5DEC1445E3FF2B39182465D933D252917ED4D4`

The snapshot includes current tracked files and non-ignored untracked files
that existed at backup time; it does not include ignored files, Git internals,
or tracked paths already deleted from the worktree. Preserve the original
evidence directories as well.

The archive SHA-256 was rechecked on 2026-10-17 and matches the value above.
A fresh baseline was captured at
`artifacts/evidence/baseline-20261017-200644/`. It contains
`git-head.txt`, `git-status.txt`, `git-diff-stat.txt`, `untracked-files.txt`,
and `artifact-sha256.csv`. This manifest hashes files under `artifacts/`; it
does not claim to hash ignored build outputs or record tool versions. Capture
those in the run manifest before starting a build.

The current checkout is heavily dirty, so no clean-release claim can be made
from it. Existing audit reports are dated snapshots; regenerate the relevant
gates before relying on their detailed statuses.

### Execution log — 2026-10-17

- Pre-change snapshot: `D:\SEB BRO-execution-backup-20261017-201023.zip`,
  SHA-256 `a6d8678cc1b0acc87f2c6db0dc5c0cae79781a71fc1bb227c385894d0c8c2893`
  (667 current tracked/non-ignored files; no unreadable files skipped).
- Fixed the TPM sealing manifest to seal the ledger/session journal HMAC key
  once under the key name and environment variable actually consumed by both
  server components. Removed the unused duplicate session-key bundle entry.
- Removed fixed development tokens, event/variant keys, demo exam URL/name/
  duration, fake device ID, plaintext admin password, and fixed root/exam
  passwords from the VMware image builder. Removed its unseal and development
  mode bypasses; resulting images require normal deployment provisioning.
  Changed its workspace, cache, temporary mount, and output locations to
  per-run/configurable paths; it no longer detaches global loop devices or
  deletes shared workspaces or prior VMDKs. Existing output paths are rejected.
- Added `tests/p0/tpm-secret-mapping-test.sh`, a non-TPM static regression for
  those contracts. WSL Bash syntax checks and that regression passed. A
  repository-wide `git diff --check` reports pre-existing whitespace in old
  logs/docs; targeted changed-file checks are tracked separately. No TPM
  operation, image build, or artifact overwrite was performed.
- This is one remediation increment, not completion of the implementation
  plan. Phase gates and production readiness remain unverified/blocked.

### Execution log — 2026-10-18

- Preserved the current pre-increment dirty worktree in
  `D:\SEB BRO-execution-backup-20261018-0847.zip`; SHA-256
  `9ffe313c3a24aac17e62b34e5738877fdf5a2d04243439ec4ea9dac38de942c7`.
  ZIP CRC validation passed. The snapshot contains 725 entries, including
  two WSL symlinks preserved as link metadata; four paths already deleted in
  the worktree are recorded in the sidecar. Ignored outputs were inventoried,
  not copied. The Phase 0 manifest and 218 artifact hashes are in
  `../artifacts/evidence/phase0-inventory-20261018T031811Z/`.
- Restricted development-only plain HTTP exam origins to the exact
  `127.0.0.1:8000` and `localhost:8000` endpoints in the server validator and
  Chromium policy generator. Added positive and negative regression cases
  for both loopback forms and missing/non-admin ports.
- The Chromium policy generator regression passed 13 assertions under
  Windows Git Bash using the installed Python runtime. P1 source validation
  produced 41 PASS, 0 FAIL, and 1 BLOCKED (`EXAM_URL=NOT_CONFIGURED`).
  Changed-script syntax and targeted `git diff --check` passed. The C URL
  validator test was not run because no compiler is available in Windows and
  the WSL Ubuntu invocation failed to start.
- Phase 1 image/kiosk acceptance remains BLOCKED: there is no approved
  staging exam URL, isolated clean candidate build, working build toolchain,
  or QEMU runtime in this session. No image, VM, hardware, runtime P2, or
  release claim was produced. Phases 2–7 remain blocked/not started pending
  their Phase 1 exit and the trust, privacy, hardware, assessor, and pilot
  prerequisites described below. See the run-specific report under
  `../artifacts/evidence/phase1-source-validation-20261018T0320Z/`.
- Ran the safe host-only P2 static audit into a unique evidence directory:
  49 static checks PASS, 0 FAIL, 0 BLOCKED. The Chromium policy suite had
  3 static PASS and 3 runtime BLOCKED (Chromium/kiosk unavailable); the P0
  TPM secret-mapping static regression passed. Phase 2 remains BLOCKED because
  no current image or isolated booted guest was available. WSL execution
  returned `Wsl/Service/E_UNEXPECTED` and the Docker Desktop daemon was
  stopped; shared virtualization services were not restarted. See
  `../artifacts/evidence/phase2-static-host-20261018T0905Z/`.
- Restarted only `Ubuntu-26.04` with `wsl.exe --terminate Ubuntu-26.04`; a
  sequential shell probe then succeeded. Journal evidence shows WSL had timed
  out waiting for user session UID 1000 during parallel WSL launches; one
  sequential WSL command now exits cleanly. No Linux distro was reset and the
  Docker Desktop distro/service was not changed.
- Reproduced and fixed two native build blockers in the dirty source snapshot:
  a nested `/*` sequence in a `server/main.c` block comment triggered
  `-Werror=comment`, and an unmatched brace in
  `platform_update_exam_url()` placed the trailing unlock/return outside the
  function. The latter produced parser and `-Werror=return-type` diagnostics.
  The full server build and all native C/C++ subsystem builds then passed in
  isolated output directories. The exact-origin C validator test passed all
  22 cases; the P0 server integration smoke passed 11/11 checks. Deprecated
  OpenSSL SHA-256 API warnings remain, as already allowed by the repository
  build flags; this run does not certify a clean commit or release.
- Re-ran P2 static checks in WSL: 49 PASS, 0 FAIL; Chromium policy static
  checks 3 PASS, 3 runtime BLOCKED; USB policy 5 PASS, 0 FAIL, 3 BLOCKED
  because WSL exposes no host USB controller/USBGuard daemon and hardware
  testing was explicitly disabled. P1 source validation remains 41 PASS,
  0 FAIL, 1 BLOCKED (`EXAM_URL=NOT_CONFIGURED`). No current image, QEMU boot,
  kiosk flow, guest P2 matrix, physical-device, trust, privacy, assessor, or
  pilot gate passed. Run details are in
  `../artifacts/evidence/wsl-recovery-native-20261018T0955Z/`.
- Source-only remediation increment against dirty HEAD
  `c8d8c6149458e9c1611966d5f2db66ed2f42e2d1` (146 tracked paths modified at
  validation; no clean-commit claim): removed fabricated release measurements
  and left `server/config/releases.json` empty; removed runtime sample/default
  exam state and made unprovisioned exam, policy, attestation, remote-device,
  center-command, heartbeat, and submission flows fail closed; restricted
  runtime trust enrollment/revocation to explicit development mode and marked
  those records runtime-only; removed fake hardware telemetry, version,
  health, staff, retention, backup, and enforcement claims; changed unknown
  telemetry to `null` and marked platform state `NOT_PRODUCTION_READY`; and
  tightened exam config parsing and storage input checks. No production data
  or trust inputs were generated.
- Validation: strict server build passed with GCC 15.2.0/OpenSSL 3.5.5 in
  WSL2 using `make -C server BUILD_DIR=/tmp/examos-validation-final3
  TARGET=examos-server`; the exact-origin C URL regression passed 22 cases;
  `tests/server/unprovisioned-fail-closed-test.c` passed the exam, policy,
  storage, fleet, and no-data reconciliation checks; the empty release JSON
  and unconfigured exam config checks passed; targeted `git diff --check`
  reported no whitespace errors (Git emitted only its existing LF/CRLF
  conversion warnings). The first strict build exposed an unbounded
  exam-question array access; the loop bounds were corrected before the
  passing rebuild.
- This validates compilation and narrow source contracts only. P0/P1 runtime,
  P2 guest, physical TPM/device, real exam content, trusted release-signing,
  durable platform registry, privacy/governance, independent assessor, and
  pilot gates were not run or passed. Synthetic-registry integration tests
  were deliberately not run as production evidence. Production remains
  BLOCKED; see issue-register entries E-08, A-20, and A-21.

## Delivery phases

### Phase 0 — Freeze and reconcile the baseline

**Objective:** establish exactly what source and evidence are present without
changing existing outputs.

- Record commit, complete modified/staged/deleted/untracked status, ignored
  build outputs, artifact hashes, host/guest/toolchain versions, and exact
  commands. Preserve the resulting manifest outside generated build output.
- Inventory every artifact by phase, digest, source binding, and evidence class.
- Reconcile split P0 records with gate schemas; mark stale/mismatched records.
- Resolve contradictory status statements in older docs only after fresh
  evidence exists; preserve historical reports.

**Acceptance:** backup hash verifies; manifest has HEAD, all Git status
categories, ignored-output inventory, artifact SHA-256, host/tool versions,
timestamp, and command log; every evidence item is labelled source commit,
source dirty/clean, artifact digest, and development/VM/physical/independent
class. Any missing field is `UNKNOWN`; no phase status is inferred from it.

**Exit:** an immutable source snapshot and evidence index exist; each phase
has one current status backed by identified artifacts. Dirty-tree evidence
remains development-only.

### Phase 1 — Build and kiosk acceptance (P0/P1)

**Objective:** reproducibly build and boot the actual candidate image into the
restricted examination flow.

- Build from a clean identified commit; record pinned dependencies, toolchain,
  SBOM, image/UKI/root digests, and reproducibility comparison.
- Use a new isolated worktree and unique output directory for every run. Pin
  package repository snapshots and dependency versions; record build scripts,
  environment, configuration inputs, and source-to-image provenance manifest.
- Pass current-image QEMU/OVMF disk and ISO boot, first boot, recovery, and
  kiosk-to-approved-exam-URL flows. Test expected failures and escape paths.
- Validate the declared supported hardware matrix separately; VM results are
  not physical results.

**Acceptance:** two clean builds from the same pinned source/config produce
identical declared reproducible outputs (or documented, reviewed normalized
differences); provenance binds commit/tree digest, dependencies, configuration,
builder, and all output digests. Each P0/P1 check has expected result, actual
result, evidence path, and failure/block reason. First boot, approved exam URL,
kiosk restrictions, disallowed navigation/input, process failure, network
failure, and recovery have explicit passing assertions.

**Exit:** current-image P0 and P1 gates pass with source/artifact binding;
negative boot and kiosk bypass tests fail closed; rollback/recovery works.

### Phase 2 — Runtime OS lockdown

**Objective:** prove that configured controls are enforced in a running guest.

- Run the 20 mandatory P2 checks in an isolated booted guest: firewall
  allow/deny, AppArmor enforcement, USB policy, dm-verity clean and corruption
  boot, module/sysctl policy, Chromium policy, service confinement, and
  recovery.
- Keep physical USB and external network scan results as separate evidence.
- Bind each result to the exact image, source snapshot, and deployment config.

**Acceptance:** the maintained matrix names each mandatory test, control,
precondition, expected result, actual result, evidence path, result status,
failure reason, image digest, and run ID. Every mandatory row is PASS before
the phase can pass; BLOCKED, NOT_RUN, and static-only checks remain distinct.

**Exit:** all mandatory VM checks pass; required hardware checks pass on every
declared device class. Static configuration checks alone do not pass this
phase.

### Phase 3 — Device identity, attestation, and key release

**Objective:** authenticate an enrolled device and release exam secrets only
for an authorized, currently trusted session.

- Decide and document production trust authority, enrollment ceremony, EK/AK
  identity validation, revocation, approved release manifests, PCR policy,
  key custody, and recovery.
- Specify quote freshness using a server-generated unpredictable nonce,
  single-use challenge ID, expiry, device/session/release binding, verified
  quote signature, enrolled EK/AK identity, approved PCR policy, event-log
  replay to quoted PCR values, current revocation status, and fail-closed
  authorization. Release only the minimum exam/session key after all checks
  pass; audit decision inputs and deny reasons without logging key material.
- Complete reviewed event-log parsing/replay and bind raw log, server nonce,
  quote, release identity, device identity, and session.
- Add reviewed TLS/mTLS transport, administrator authentication/MFA, scoped
  authorization, rate limits, durable transactional state, audit, backups,
  restore drills, migrations, monitoring, and incident response.
- Keep `swtpm` and synthetic registry results labelled development evidence.

**Acceptance:** documented trust-authority owner and key ceremony; tests for
missing/expired/replayed nonce, wrong device/session/release, invalid quote,
PCR mismatch, malformed or mismatched event log, revoked device/key, policy
version mismatch, and registry/signature failure all deny release. A valid
case succeeds only with enrolled physical TPM and signed production policy.

**Central management acceptance:** inventory exposes stable registry ID,
cryptographic identity reference, institution/site/group, software/release,
last authenticated check-in, and separately derived trust state. Every
configuration/command has a scoped role, device/group target, expiry or
replay protection, authenticated signature, audit event, and result receipt.
Updates are signed, staged by cohort, health-checked, rollback-capable, and
revocable. Recovery and unenrollment revoke credentials and retain only
policy-approved audit records. Student-owned device management requires
explicit consent and cannot access personal files, camera, or microphone
outside the approved exam flow.

**Exit:** release gate passes on real enrolled physical TPMs with production
trust inputs; independent reviewer verifies replay, revocation, mismatch,
recovery, and key-release denial cases.

### Phase 4 — Security events and proctoring governance

**Objective:** produce reliable, privacy-governed evidence with bounded human
interpretation.

- Decide whether automated video analysis is necessary and proportionate.
- Approve licensed, pinned model artifacts and provenance before packaging.
- Establish informed consent, retention/deletion, access logging, accessibility,
  candidate appeal, human review, and incident handling.
- Evaluate on consented, representative, independently labelled data with
  predeclared metrics, subgroup/error bounds, and false-positive/negative
  reporting. Synthetic fixtures validate code paths only.
- Exercise tamper resistance, clock alignment, concurrency, overload, outage,
  evidence export, and deletion.

**Acceptance:** a data inventory records purpose, fields, source, access roles,
storage location, retention period, deletion method, and audit evidence.
Consent can be withdrawn where applicable; deletion is verified across primary
storage, exports, and backup lifecycle. Candidate notices, accessible flows,
appeal route, human decision owner, incident review, and prohibition on
automated guilt decisions are documented and exercised. The exam workflow
persists authenticated candidate/session-bound answers durably, rejects
duplicate/replayed/tampered submissions, returns a verifiable receipt, and
recovers correctly after power/network interruption.

**Exit:** governance approval and independent real-data evaluation pass; event
integrity and operational controls pass. No claim that alerts prove cheating.

### Phase 5 — Candidate workflows and exam operations

**Objective:** validate exam lifecycle, candidate support, and fair incident
review end to end.

- Finish authentication-bound session and answer handling, durable submission,
  duplicate/replay protection, provider outage behavior, and exam closure.
- Validate accommodations, accessibility, consent, human review, appeals,
  invigilator training, staffing ratios, escalation, and audit reports.
- Test backup/restore, power loss, network loss, offline authorization and
  synchronization only if offline exams are explicitly designed and approved.

**Exit:** non-stakes end-to-end exercises pass with real operational roles,
documented recovery, and privacy/legal review for target jurisdictions.

### Phase 6 — Independent assessment and controlled pilot

**Objective:** establish that release controls withstand independent review
and real operations.

- Obtain written scope and authorization for red-team work on owned systems.
- Remediate findings and retest the original cases; no unresolved critical
  findings, and high-risk findings receive documented independent disposition.
- Run a small, informed, non-stakes pilot across the approved device matrix;
  include rollback, support, accessibility, incident handling, and cost data.
- Complete independent release review, key ceremony, recovery exercise, and
  operational readiness sign-off.

**Approval separation:** name (by role or named person) the system owner,
security finding severity approver, remediation owner, independent retest
assessor, privacy/legal reviewer, operational pilot owner, and release
authority. The developer who implemented a control cannot be its sole
independent assessor or final release approver. Unassigned roles block exit.

**Exit:** every production prerequisite is evidenced and approved by named
owners. Green dashboards do not replace this review.

### Phase 7 — Commercial launch and measured scaling

**Objective:** launch only the validated scope and expand based on customer
and delivery evidence.

- Start with college-owned labs and a narrowly supported hardware matrix.
- Use paid pilots and customer interviews to validate licence, deployment,
  monitoring, and invigilation pricing hypotheses.
- Track per-customer delivery cost, utilization, support burden, renewal,
  hosting, insurance, taxes, and collection time before hiring or expansion.
- Publish clear service boundaries, uptime/support expectations, data
  processing terms, incident communications, and recovery responsibilities.

**Acceptance:** customer onboarding checklist, supported hardware and network
matrix, service description, availability/support hours, severity-based
response targets, escalation contacts, maintenance/rollback procedure,
incident notification timelines, data-processing/security terms, privacy
responsibilities, exit/data-return process, insurance/tax review, and per-site
cost model are approved before a paid deployment. Commitments must match
measured staffing and pilot performance; do not publish unsupported SLA values.

**Exit:** signed demand and measured unit economics support expansion; security
and privacy approvals remain current.

## Immediate implementation queue

| Priority | Work item | Owner | Evidence / done condition | Dependency |
|---|---|---|---|---|
| 0 | Preserve dirty worktree and create baseline index | Engineering | External backup hash plus new evidence manifest | Local workspace |
| 1 | Reconcile present P0/P1 artifact hashes and rerun the smallest safe source checks | Engineering | Fresh, isolated report with commit/tree/image digests | Build host/toolchain; no overwrite |
| 2 | Restore current-image P0/P1 boot and kiosk pass | OS engineering | Boot logs and guest assertions tied to same image digest | Working QEMU/OVMF or supported device |
| 3 | Run P2 mandatory guest tests | OS/security QA | Per-test result matrix, including negative cases | Bootable guest and deployment inputs |
| 4 | Finish P3 trust design and transport/storage controls | Security/backend | Reviewed design plus implementation and threat tests | Trust authority, TLS identity, key custody |
| 5 | Decide proctoring scope and governance | Product/privacy | Written necessity, consent, retention, model/data approvals | Institution and privacy/legal owners |
| 6 | Complete P5 workflow and operations | Product/operations | Non-stakes rehearsal, recovery and fairness evidence | Approved provider and operational roles |
| 7 | Independent assessment and pilot | Independent assessor/operations | Findings, retests, pilot report and approvals | Written authorization, hardware, volunteers |

## Required test evidence matrix

Maintain one row per mandatory test (including negative and recovery cases)
in the phase test matrix and generated run report:

| Field | Required value |
|---|---|
| Test ID / requirement | Stable ID mapped to a threat/control and release criterion |
| Preconditions | Exact image, deployment config, services, hardware class, and fixtures |
| Expected result | Observable assertion, including expected denial/failure behavior |
| Actual result | Captured output and assertion result; never infer from script exit alone |
| Status | PASS, FAIL, BLOCKED, NOT_RUN, or INVALIDATED with documented semantics |
| Evidence | New run-specific path, SHA-256, logs, and machine-readable result |
| Provenance | Commit, dirty state, source/tree digest, image digest, tool versions, command |
| Failure/block reason | Required for every non-PASS result, with owner and next action |

No suite-level PASS if a mandatory row is missing, stale, mismatched to the
image/source, or BLOCKED/NOT_RUN/INVALIDATED.

## Correct implementation order

1. **Protect and inventory:** verify the archive hash; capture Git commit,
   staged/modified/deleted/untracked paths, ignored outputs, artifact hashes,
   and tool versions. Inspect scripts and output paths. Never reset, clean, or
   overwrite prior evidence.
2. **Repair P0/P1 acceptance:** in an isolated QEMU/OVMF environment and a
   unique output directory, build and boot the identified image; test first
   boot, approved URL, kiosk restrictions, failure handling, and recovery.
3. **Prove P2 runtime security:** boot the guest and execute the full mandatory
   matrix, including enforced AppArmor, firewall allow/deny, USB authorization,
   and dm-verity corruption rejection.
4. **Complete trusted device management:** implement and test TPM trust,
   authenticated/authorized APIs, central inventory and grouping, health,
   signed staged updates, durable audit/persistence, backup, restore, and
   device recovery.
5. **Complete exam operations and independent testing:** verify durable exam
   sessions and answer submission through network/power failures; verify
   privacy, accessibility, appeals, and incident review; conduct authorized
   independent assessment and retest.
6. **Pilot, then sell:** run a small non-stakes pilot on institution-owned
   devices; measure failures, recovery, support load, and per-customer cost.
   Expand only after evidence and operating commitments are approved.

This ordering does not imply any phase has passed. Work that requires an
external trust authority, physical hardware, consented participants, or an
independent assessor remains blocked until that dependency is supplied.

## Commands and change control

Do not run `make clean` or destructive image/build scripts against the current
dirty checkout. Use a separate clean worktree or clone after preserving and
reviewing the current modifications. Before each authorized validation, inspect
the script and its output paths, then direct outputs into a new run directory.

Repository-level safe inventory commands:

```powershell
git rev-parse HEAD
git status --short --branch
git diff --stat
git ls-files --others --exclude-standard
```

The project Makefile exposes `make all`, phase gates, and `make clean`; these
must be run only in an isolated clean checkout with dependencies verified.
Current Windows/WSL context and missing external approvals mean the full plan
cannot be certified from this worktree alone. Complete local code and
documentation tasks can proceed phase by phase, while hardware, trust-root,
privacy, red-team, and pilot gates remain explicitly blocked until their
required owners and evidence exist.

## Business assumptions

The ₹1 crore annual revenue objective and prices in the supplied master plan
are hypotheses, not forecasts. Validate through customer interviews and paid
pilots. Model software/support, deployment, and examination operations as
separate services and calculate gross margin and working capital for each.
Do not offer production security or detection guarantees that exceed validated
evidence.
