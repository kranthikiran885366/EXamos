# ExamOS Phase 1 execution report

**Run ID:** `phase1-source-validation-20261018T0320Z`  
**Source revision:** `c8d8c6149458e9c1611966d5f2db66ed2f42e2d1`  
**Branch:** `work/p0-secure-release-remediation-20261011`  
**Worktree:** Dirty  
**Classification:** Windows development/source validation only

## Scope

Restricted plain-HTTP exam origins to the exact development admin endpoints
`http://127.0.0.1:8000` and `http://localhost:8000`. The server validator,
Chromium policy generator, admin API error text, and regression cases now
agree on that restriction. HTTPS origins continue to use the canonical
configured origin; no subdomain wildcard is added.

## Results

| ID | Check | Status | Result |
|---|---|---|---|
| DYN-01 | Chromium policy generator exact-origin and URL rejection cases | PASS | 13 assertions passed under Windows Git Bash and Python 3.11.9 |
| DYN-02 | C config/platform URL validator unit test | NOT_RUN | No GCC/Clang; WSL Ubuntu invocation did not start |
| DYN-03 | P1 source validation | BLOCKED | 41 PASS, 0 FAIL, 1 BLOCKED: `EXAM_URL=NOT_CONFIGURED` |
| DYN-04 | Changed shell syntax and targeted whitespace check | PASS | Both `bash -n` checks and targeted `git diff --check` exited 0 |
| BUILD-01 | Full native server build | NOT_RUN | Compiler/build toolchain unavailable |
| IMG-01 | Current image build, boot, and kiosk acceptance | NOT_RUN | No approved staging URL, isolated clean build, or QEMU runtime |
| P2 | Guest runtime lockdown matrix | BLOCKED | No current Phase 1 candidate image or isolated booted guest |
| P3–P7 | Trust, governance, operations, independent assessment, and launch | BLOCKED / NOT_RUN | Their external trust, consent, hardware, assessor, provider, and pilot prerequisites are absent |

**Phase 1 gate decision: BLOCKED.** The dynamic-origin source increment passed
its focused regression, but that does not pass P0/P1 image, boot, kiosk,
network, hardware, or release acceptance. The existing historical P1 `FAIL`
and P2 `NOT_RUN` evidence is not promoted or overwritten.

## Evidence and provenance

- Exact changed-source hashes: [`source-sha256.csv`](source-sha256.csv)
- Test/log hashes: [`evidence-sha256.csv`](evidence-sha256.csv)
- Full disposition matrix: [`test-matrix.csv`](test-matrix.csv)
- Commands, dirty state, and scope: [`run-manifest.txt`](run-manifest.txt)
- Tool limitations: [`tool-versions.txt`](tool-versions.txt)
- Generator test result: [`chromium-policy-generator-test-final.log`](chromium-policy-generator-test-final.log)
- P1 source result: [`p1-source-validation-gitbash.log`](p1-source-validation-gitbash.log)
- Syntax/whitespace result: [`validation-integrity.log`](validation-integrity.log)

## Required before continuing Phase 1

1. Supply an approved non-production exam URL/origin without credentials or
   tokens; the committed fail-closed configuration must remain unconfigured.
2. Use an isolated Linux build host with the pinned toolchain and working
   mkosi, GCC, QEMU/OVMF, and output paths. Build from an identified clean
   source snapshot without overwriting existing evidence.
3. Re-run the C URL-validator test, full source/build gates, two-build
   reproducibility check, and current-image boot/kiosk/recovery tests with
   run-specific logs and artifact digests.

Phases 2–7 cannot be promoted until their ordered prerequisites are met.
Physical TPM/firmware/disk/media operations, production key custody, consented
data collection, independent assessment, and pilot activity were not
performed.
