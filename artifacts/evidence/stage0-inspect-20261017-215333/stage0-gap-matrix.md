# ExamOS — Stage 0 source-grounded gap matrix

**Stage:** 0 (Protect and inspect)
**Date:** 2026-10-17
**Repository:** `d:\SEB BRO` (local-only, no remote)
**Branch:** `work/p0-secure-release-remediation-20261011`
**HEAD:** `c8d8c6149458e9c1611966d5f2db66ed2f42e2d1` (short `c8d8c61`; `v0.1.0-1-gc8d8c61`; tag `v0.2.0` at `878093c`)
**Working tree:** heavily dirty (many modified / staged-deleted / untracked files — see sibling `git-status.txt`, `untracked-files.txt`)
**Backups:** verified external recovery baseline exists (see `backup-verification.txt`)
**Scope:** read-only inspection. No source modified, no destructive operation, no production-readiness claim.
**Authoritative prior audit:** [`docs/security/END_TO_END_AUDIT.md`](../../../docs/security/END_TO_END_AUDIT.md) — decision BLOCKED / NOT APPROVED FOR LIVE EXAMINATIONS.

This matrix is grounded in actual source reads (server C, agent C, kiosk C, proctoring C++, image configs) plus the context-gatherer inventory. Where a claim could not be verified from source, it says so.

---

## 1. What currently exists (architecture snapshot)

A single-process, multi-threaded **native C** raw-socket HTTP/1.1 server (`server/main.c`) bound to `127.0.0.1:8000`, with a C security agent (`agent/`), a Cage/Wayland Chromium kiosk launcher (`kiosk/launcher/`, C), a C++ V4L2 proctoring engine (`proctoring/`), and a Debian Trixie/mkosi OS image (`image/`). **There is no SQL database, no Node.js, no Mongo/Redis/Docker backend** — those appear only in older docs and the P6 prerequisite report as an unresolved product decision (see §7).

Storage is flat, append-only, hash-chained + HMAC files (ledger, session journal, proctoring event chain), plus atomic key=value config. Exam answer/submission state is **in-memory only**.

Real cryptographic work present: a 16-check TPM attestation chain in the C server with genuine TPMS_ATTEST parsing, AK RSA/ECDSA signature verification, EK certificate-chain validation, and event-log PCR reconstruction; MakeCredential via fixed argv (no shell). A separate Go `verifier.go` is a **dev-only stub** that computes a fake shared-secret digest, not a real TPM signature.

---

## 2. Module gap matrix (A–P)

Legend: ✅ IMPLEMENTED · ◐ PARTIAL · ✗ MISSING/STUB. "Partial" = real code exists but material gaps remain.

| # | Module | Status | Primary source references | Headline gap |
|---|--------|--------|----------------------------|--------------|
| A | Enterprise Admin Dashboard | ◐ | `server/admin/admin_dashboard.c`; served by `server/main.c` GET `/admin` | Real SPA calls live APIs (`/api/v1/center/terminals`, `/center/command`, `/admin/config`), but inline HTML hardcodes telemetry ("60" seats, "< 2 ms", "TCS iON Center Master", "AES-256-GCM Hardware Sealed"); `migrateSeat()` is a client stub. Only 3 of 17 required sections are real. |
| B | Identity, AuthN, AuthZ | ◐ | `server/admin/admin_dashboard.c` `admin_check_auth`; `server/login/candidate_login.c`; `server/admin/config_manager.c` `config_verify_admin_password` | Admin = HTTP Basic + PBKDF2 + rate-limit/lockout; candidate = PIN + PBKDF2 (NO rate limit). **No MFA, no RBAC table, no tenant isolation, no admin server-side session.** `reviewer_authorized()` (`server/main.c` ~line 200) is a broad OR of admin + agent + proctor + reviewer tokens — violates least privilege. Default `NOT_PROVISIONED` (fail-closed). |
| C/D | Dynamic Exam Config & Policy Engine | ◐ | `server/admin/config_manager.c` `config_load`/`config_save`; `server/main.c` POST `/api/v1/admin/config` | URL read from config at runtime (not hardcoded in server), atomic save. **No HTTPS enforcement** (http:// accepted), **no versioning, no signing, no approval, no rollback, no distribution.** `policy_signature` is stored but NEVER verified anywhere. |
| E | Firewall & Network Security | ✅ (template+generator) | `image/overlay/etc/nftables.conf`; `image/scripts/generate-nftables.sh`; `image/overlay/etc/examos/deployment.conf` | Real default-DROP ruleset + generator with IP validation and `nft --check` rollback. Ships `DEPLOYMENT_REQUIRED` placeholders (0.0.0.1–7) — fail-closed until generated. Runtime enforcement in a booted guest is NOT_RUN (P2). |
| F | Secure Kiosk & Candidate Session | ◐ | `kiosk/launcher/launcher.c` `load_exam_url_from_config`/`main`; `image/overlay/etc/chromium/policies/managed/examos_policies.json` | Launcher reads exam URL from argv→env→exam.conf and hardens Chromium; fresh ephemeral profile per launch. **Chromium policy allowlist/camera/audio URLs hardcode `exam.examos.security` and are NOT read from exam.conf** → changing EXAM_URL breaks capture/policy. `remove_directory_recursive` uses `system("rm -rf")` (shell-injection surface if path influenced). No server-session integration; OS-level escape not addressed beyond Chromium policy. |
| G | Device Enrollment & Fleet | ◐ | `server/attestation/attestation_config.c` `attestation_config_load_devices`; `server/attestation/attestation_service.c` (`g_devices[]`); `server/main.c` `/api/v1/admin/device/register` (dev-mode only) | Real enrollment via MakeCredential/ActivateCredential and revoke. **Device table in-memory, not persisted back** (enroll/revoke lost on restart; only ledger survives). **No device groups, no health state, no unenroll, no bulk actions.** Heartbeat only appends a ledger event. |
| H | TPM Attestation & Key Release | ✅ (server) / ✗ (Go verifier) | `server/attestation/attestation_service.c` `attestation_verify_evidence` (16 checks), `tpms_attest_parse_and_verify`, `ak_quote_sig_verify`, `ek_cert_chain_validate`; `server/gateway/key_release.c` | Real cryptographic verification with nonce TTL, replay protection, device/release binding, PCR match, AK-sig verify, EK cert chain, event-log reconstruction, fail-closed production mode. **`server/attestation/verifier.go` Check-16 is a STUB** (`expectedSig = SHA256(composite + akQuoteSuffix)` — fake shared-secret, not a TPM signature) and must never authorize production. Physical TPM / signed production registries / key ceremony absent. swtpm = dev evidence only. |
| I | Central Operations Management | ◐ | `server/exam/exam_engine.c` `center_master_get_terminals_json`/`center_master_execute_command`; `server/main.c` `/api/v1/center/*`, `/api/v1/admin/device/disconnect|reconcile` | Real PAUSE/RESUME/BROADCAST mutate in-memory state. **Terminal JSON fabricates fields** (center_name "TCS-Digital-Zone-Main-Center-01", total_seats 60, battery 88, ping 2, ip 192.168.1.x, anomalies 0, "Just now"). `/device/disconnect` & `/reconcile` are ledger-only stubs. No incident escalation, no real check-in/eligibility state. |
| J | Security Events & Incidents | ◐ | `server/events/ledger.c` (HMAC hash chain, replay, closure); `server/events/event_chain.c` (per-session hash chain + checkpoint HMAC) | Durable, tamper-evident event pipeline exists. **No severity field, no dedicated event ID, no correlation ID (session_id only), no incident create/assign/timeline, no search/dedup.** |
| K | Exam Data Integrity & Submission | ◐ | `server/exam/exam_engine.c` `exam_engine_submit`/`exam_engine_get_submitted_context`; `server/main.c` `/api/v1/exam/submit` | Real content-bound SHA-256 receipt + candidate/session binding. **Answer state + receipt are in-memory only — NOT durable; a crash loses submissions.** No transactional submit, no idempotency/replay token, no server-side deadline enforcement on submit, no offline reconcile. |
| L | Updates, Release Mgmt & Recovery | ◐ | `server/attestation/attestation_config.c` `releases.json` registry; `attestation_service.c` `attestation_register_release`/`attestation_revoke_release` | "Release" = attestation golden measurements only (signed registry, revoke, production sig verify). **No OTA: no release signing for distribution, no deployment rings, no update install/verify, no automated rollback.** |
| M | Reporting, Audit & Compliance | ◐ | `server/events/ledger.c`, `server/events/event_chain.c`; `server/main.c` `/api/v1/ledger`, `/api/v1/proctoring/events` | Durable raw audit data + JSON dumps exist. **No report generation, no formatted exports, no audit-history UI, no compliance builder, no retention enforcement.** |
| N | Privacy, Accessibility, Proctoring Gov | ◐ | `proctoring/analysis/vision_engine.cpp`; `proctoring/main.cpp` (V4L2 + enforced TLS); `server/environment/e1_consent.c`; `server/main.c` `/api/v1/consent`, `/api/v1/e1/consent` | Real OpenCV DNN detection (conditional `-DEXAMOS_USE_OPENCV`), fail-closed `MODEL_UNAVAILABLE`; consent recorded to event chain. **OpenCV not linked/packaged by `proctoring/Makefile`/`image/mkosi.conf`; no real labelled dataset; `retention_days:30` hardcoded; no WCAG; consent payload hardcodes camera/mic true; e1 always reports DISABLED_BY_POLICY.** |
| O | Infrastructure & Service Reliability | ◐ | `server/main.c` `/api/v1/health`, `/api/v1/status`, `/api/v1/desktop/telemetry`; ledger/session replay recovery; worker-slot cap (default 64) | Health endpoints + crash-recovery replay exist. **No metrics endpoint, no schema migrations, no backup/restore tooling in server, no TLS/mTLS** (loopback HTTP only). `/desktop/telemetry` has many hardcoded fallbacks (volume 80, mic 65, SSID "ExamOS-Secure-LAN"/"ExamOS-Airgap-Network", signal_dbm -45…). |
| P | Commercial & Multi-Tenant Readiness | ✗ | (no tenant code) | **No multi-tenancy, no institution/site hierarchy in code, no tenant isolation, no onboarding/exit workflows, no cost/SLA tracking.** Single shared config + candidate store. Out of scope until B/C/D/G + privacy/pilot gates pass. |

### Per-module detail (highest-impact gaps)

**Module A — Dashboard.** `admin_dashboard_html()` returns a full inline HTML/CSS/JS single-page app that polls real endpoints. Only Overview, Exam Config, and Live Operations are real. Institutions/campuses/rooms, roles, device inventory/groups, security policy mgmt, security events/incidents, attestation/compliance, releases/updates, reports/audit, backup/health, and retention are not implemented as real sections. Telemetry in the HTML is decorative/hardcoded.

**Module B — Identity.** Two hardcoded admin usernames (`admin`, `examos`) accepted in `admin_dashboard.c`. No role objects, no permission checks beyond "is admin". `candidate_group` is a stored string, not an enforced scope. No CSRF token on the admin POST routes (Basic auth + same-origin CSP mitigate but not a CSRF token). No credential rotation, no audit of admin access to sensitive records.

**Modules C/D — Config & policy.** `config_save` writes atomically (tmp+fsync+rename) but overwrites in place — no history, no version, no signature, no approval, no rollback, no authenticated distribution channel to kiosk (the kiosk reads the same flat file). `policy_signature` accepted from the client and stored; no public key, no verify call anywhere (grep confirms).

**Module F — Kiosk.** This is the direct conflict with the user's hard rule "the admin-configured exam URL is dynamic; never hardcode one universal exam URL into the OS or security policies." The launcher itself reads the URL dynamically, but the Chromium managed policy (`examos_policies.json` URLAllowlist / VideoCaptureAllowedUrls / AudioCaptureAllowedUrls) is pinned to `https://exam.examos.security/*` and `*.examos.security/*`. So an admin who changes EXAM_URL via the dashboard gets a mismatched policy.

**Module H — Attestation.** Server path is the strongest part of the codebase. Note `EXAMOS_TPM_MODE=production` enforces signed registries + EK cert chain + enrolled AK; `development` allows TOFU and relaxes EK-cert/PCR-digest mismatch. The Go verifier must be treated as non-authoritative.

---

## 3. Critical findings — hardcoded / fabricated / placeholder values

Per the project rule forbidding hardcoded data and a universal exam URL, the following must be addressed (file: location):

1. **Universal exam URL in shipped config** — `image/overlay/etc/examos/exam.conf:5` ships `EXAM_URL=https://exam.examos.security/` despite a "Do NOT edit manually" comment.
2. **Hardcoded exam domain in Chromium policy (not read from exam.conf)** — `image/overlay/etc/chromium/policies/managed/examos_policies.json` URLAllowlist / VideoCaptureAllowedUrls / AudioCaptureAllowedUrls (`https://exam.examos.security/*`, `*.examos.security/*`); also mirrored at `image/overlay/etc/opt/chrome/policies/managed/examos_policies.json`.
3. **Fabricated terminal telemetry** — `server/exam/exam_engine.c` `center_master_get_terminals_json` (center_name "TCS-Digital-Zone-Main-Center-01", total_seats 60, battery_percent 88, ping_ms 2, ip 192.168.1.<101+i>, anomalies 0, last_ping "Just now").
4. **Fabricated exam paper** — `server/exam/exam_engine.c` `exam_engine_init` (5 hardcoded questions, `correct_option` always 0; title "ExamOS NQT Advanced Enterprise Assessment"; duration 7200).
5. **Dashboard decorative telemetry** — `server/admin/admin_dashboard.c` `admin_dashboard_html` ("< 2 ms", "60", "TCS iON Center Master", "AES-256-GCM Hardware Sealed", "TPM 2.0 PCR Attested (SHA-256)").
6. **Hardcoded consent payload** — `server/main.c` `/api/v1/consent` (`{"camera_consent":true,"microphone_consent":true,"retention_days":30}`).
7. **Hardcoded heartbeat response** — `server/main.c` `/api/v1/heartbeat` returns `"block_index":1` regardless of actual ledger index.
8. **Hardcoded default session IDs** — `server/main.c` proctoring/second-camera routes default `session_id` to `"exam-session-01"`; `proctoring/main.cpp` defaults session_id/server_url/video_dev.
9. **Fake quote-signature formula (dev-only)** — `server/attestation/verifier.go` Check-16 (`expectedSig = SHA256(composite + EXAMOS_AK_QUOTE_SUFFIX)`); the C server removed this — Go verifier must not authorize.
10. **Config-save defaults** — `server/admin/config_manager.c` `config_save` (EXAM_ID "EXAM-MAIN-001", EXAM_NAME "ExamOS Secure Exam", permitted_apps "chromium,calculator", policy_signature "UNSET", candidate_group "ALL_GROUPS", duration 120).
11. **Placeholder firewall IPs** — `image/overlay/etc/nftables.conf` (0.0.0.1–0.0.0.7) — intentional fail-closed, not production values.
12. **Telemetry fallbacks** — `server/main.c` `/api/v1/desktop/telemetry` (volume_percent 80, mic_level_percent 65, network_ssid "ExamOS-Secure-LAN"/"ExamOS-Airgap-Network", signal_dbm -45/-52/-35/-40).

Items 1–2 directly violate the dynamic-URL rule and are the highest-priority fixes.

---

## 4. Phase evidence status (from `docs/security/END_TO_END_AUDIT.md`, corroborated by artifacts)

| Phase | Status | Key blocker |
|-------|--------|-------------|
| P0 build/boot | BLOCKED | Current disk digest `c0b4619a…997b00af`; recorded boot/first-boot PASS binds to older `a531ad41…1361de3f`; ISO optical boot FAILs (QEMU exit 139); tree dirty; no physical device qualified. |
| P1 kiosk+network | FAIL | `artifacts/p1/results.json`: artifact_exists + guest_boot fail; exam_url/performance BLOCKED. |
| P2 OS lockdown | NOT_RUN | `artifacts/phase2/phase2-manifest.json` says NOT_RUN; 20 mandatory tests unrun; only static config exists. |
| P3 attestation+key release | INVALIDATED | `artifacts/p3/results.json` INVALIDATED (dirty tree; aborted at P3-014); 18/18 swtpm suite is dev-only. |
| P4 proctoring+event integrity | INVALIDATED | `artifacts/phase4/phase4-manifest.json` INVALIDATED (fabricated data; regression FAIL); OpenCV not packaged/enabled. |
| P5 behavior/viva/human review | BLOCKED | P5-A–E pass recorded; P5-F/G/H/I blocked (viva provider unavailable; fresh P0–P4 evidence absent). |
| P6 production prerequisites | BLOCKED | Architecture decision (Node/Mongo/Redis/SFU/Docker vs native C), hardware matrix, red-team, pilot, key custody, real P4 data, P5 provider all unmet. |

No phase may be promoted to PASS while BLOCKED/NOT_RUN/INVALIDATED. Historical PASS reports bind to older digests and must not be reused.

---

## 5. API surface summary (real routes that exist)

`server/main.c` registers (auth noted): `/` (login HTML); `POST /api/v1/candidate/login`; `GET /admin`; `POST /api/v1/admin/config|schedule|policies|groups/assign|device/disconnect|device/reconcile|revoke/release|release/register|device/register|reload|lock|revoke/device`; `POST /api/v1/attestation/nonce|verify|re-attest|credential-challenge|credential-verify`; `GET /api/v1/attestation/status`; `GET /exam` & `/exam/workbench`; `GET /api/v1/exam/paper`; `POST /api/v1/exam/save_answer|submit|key-release`; `GET /api/v1/exam/announcements` (no auth — gap); `GET /api/v1/center/terminals`; `POST /api/v1/center/command`; `POST /api/v1/heartbeat`; `GET /api/v1/ledger`; `GET /api/v1/status`; `POST /api/v1/consent|e1/consent`; `POST /api/v1/proctoring/events|checkpoint|verify`; `GET /api/v1/proctoring/events`; `POST /api/v1/second-camera/request|pair`; `GET /second-camera`; `GET /api/v1/desktop/telemetry` (no auth — gap); behaviour/variant/viva routes (`/api/v1/behaviour/*`, `/api/v1/exam/variant`, `/api/v1/reviewer/*`, `/api/v1/viva/*`); `GET /api/v1/health`.

Notably missing endpoints (per the required API contract): institutions/tenants, roles/permissions, candidates/roster/eligibility (beyond PIN login), device groups/health/bulk ops, policy versioning/approval/distribution, exam lifecycle state transitions (draft→approval→schedule→open→closure→reconcile), submissions reconciliation, security-event search/incidents, releases/update distribution, reports/exports, backups/restore. These are the contract gaps to implement.

---

## 6. Recommended safest isolated execution environment (task)

- **Do NOT build/run `make clean` or image scripts against the current dirty checkout** (per implementation plan). The tree diverges from HEAD; building here risks overwriting existing evidence.
- **Use a separate clean worktree from the current local repo** (no remote exists, so `git worktree add` from `d:\SEB BRO`): create a new worktree at a fresh path, e.g. `d:\SEB BRO-wt-stage1-<timestamp>`, off a chosen commit (or the current branch tip after reviewing dirty changes). Keep the original `d:\SEB BRO` untouched as the dirty-source preserve.
- **Unique output directory per run** for all build/test artifacts — e.g. `artifacts/evidence/<phase>-<runid>/` — never reuse or overwrite existing evidence dirs. Each run records commit, dirty state, image/config digests, tool versions, commands, PASS/FAIL/BLOCKED per test.
- **Windows/WSL constraint:** the Makefile and scripts use bash idioms (`command -v go`, `$(MAKE) -C`), so native builds run under **WSL (Ubuntu)**, not PowerShell. QEMU/OVMF, mkosi, swtpm, tpm2-tools, OpenSSL must be present in WSL; `tests/p0/host-check.sh` / `scripts/examos-doctor.sh` verify readiness.
- **Physical/production gates remain blocked:** any test needing physical TPM, real EK cert chains, signed production registries, TLS/mTLS, consented participants, or an independent assessor is BLOCKED until those owners/inputs exist. Run those as explicitly dev/VM evidence only.
- **Recommended first safe steps (no external dependency):** (a) remove the hardcoded universal exam URL + hardcoded Chromium allowlist domain (Modules C/F, findings 1–2); (b) add HTTPS enforcement to exam-URL validation; (c) replace fabricated terminal telemetry with real fields-or-unavailable; (d) persist device table and exam submissions durably. Each as a small, reviewed, audited commit on the worktree, with WSL `bash -n`/build verification.

---

## 7. Architecture decision that must be resolved (blocked, not to be silently changed)

The P6 prerequisite report (`tests/p6/prerequisite-audit.py` → `docs/phase6/prerequisite-status.md`) and older docs assume Node/Mongo/Redis/Python/SFU/Docker. The **actual frozen architecture is native C/C++** (confirmed by source). Per the preservation rules, the native-C design must not be silently replaced. This is a product-owner decision: either (a) accept the native-C architecture and update the P6 prerequisites/required-stack references, or (b) explicitly approve a migration with documented incompatibility. Until resolved, any "production readiness" claim against the Node/Mongo stack is invalid, and any silent rewrite is forbidden.

---

## 8. Stage 0 acceptance self-check

- [x] Git commit + branch recorded (HEAD `c8d8c61`, branch `work/p0-secure-release-remediation-20261011`)
- [x] All Git status categories captured (modified / staged-deleted / untracked) — `git-status.txt`, `untracked-files.txt`, `git-diff-stat.txt`
- [x] External backup SHA-256 verified against manifest (both archives match) — `backup-verification.txt`
- [x] Existing evidence preserved (no overwrite; new timestamped dir used)
- [x] Module-by-module gap matrix produced with file references (§2)
- [x] Hardcoded/fabricated values enumerated with file locations (§3)
- [x] Phase evidence status reconciled against authoritative audit (§4)
- [x] API surface and missing-contract endpoints identified (§5)
- [x] Isolated execution environment recommended (§6)
- [x] Architecture decision flagged as blocked (§7)
- [x] No destructive operation performed; no production-readiness claim made

**Stage 0 result:** inspection complete; gap matrix delivered; repository preserved. No phase gate is promoted. Production use remains NOT APPROVED.

## 9. Evidence references for this stage

- This directory: `artifacts/evidence/stage0-inspect-20261017-215333/` (`git-head.txt`, `git-status.txt`, `git-diff-stat.txt`, `untracked-files.txt`, `backup-verification.txt`, this file)
- Authoritative audit: `docs/security/END_TO_END_AUDIT.md`
- Implementation plan: `docs/EXAMOS_IMPLEMENTATION_PLAN_2026-10-17.md`
- Prior baseline: `artifacts/evidence/baseline-20261017-200644/`
- Verified backups: `D:\SEB BRO-backup-20261017-200057.zip`, `D:\SEB BRO-execution-backup-20261017-201023.zip`

Note: source line numbers above are approximate from read offsets; they should be re-confirmed by line before editing in Stage 1+.
