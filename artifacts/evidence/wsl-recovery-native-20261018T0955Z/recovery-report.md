# WSL recovery and native build execution

**Run ID:** `wsl-recovery-native-20261018T0955Z`
**Source revision:** `c8d8c6149458e9c1611966d5f2db66ed2f42e2d1`
**Branch:** `work/p0-secure-release-remediation-20261011`
**Worktree:** Dirty
**Classification:** Local development and source/integration validation only

## WSL failure diagnosis and recovery

The original `wsl.exe -d Ubuntu-26.04` invocation failed with
`Wsl/Service/E_UNEXPECTED` while several WSL client processes were still
running. Windows had no enabled Lxss/WSL operational event channel, so the
initial exception alone did not identify its cause.

After terminating only `Ubuntu-26.04` and launching it again, commands
started working. The Ubuntu journal then recorded
`systemctl is-active user@1000.service returned: failed` and
`CreateLoginSession: Timed out waiting for user session for uid=1000` during
overlapping WSL invocations. `user@1000.service` became active shortly after.
A single sequential `wsl.exe -d Ubuntu-26.04 --exec /bin/true` exited 0 without
a warning. This supports a WSL user-session startup race under concurrent
launches as the immediate cause. Do not invoke this distro concurrently for
further checks. The remaining failed `snapd` and `tpm-udev` WSL units are not
ExamOS failures; the WSL environment has no physical TPM. The Docker Desktop
distro/service was not restarted. The journal findings were inspected during
the diagnosis but no raw journal export was retained, so the race is supported
by observations rather than conclusively established as the sole cause of
the initial `E_UNEXPECTED`.

## Source fixes found during the planned build

1. `server/main.c` had a block comment containing the token sequence `/*`.
   GCC's `-Werror=comment` rejected the source. Reworded the comment without
   changing route behavior.
2. `server/admin/enterprise_platform.c` had an unmatched closing brace after
   `if (target_idx >= 0)` in `platform_update_exam_url()`. It left the final
   mutex unlock and error return outside the function, causing compile errors
   and `-Werror=return-type`. Removed the extra brace; the success/error paths
   are now inside the function as intended.
3. A build command initially passed a path containing spaces to GNU Make
   without quoting the variable value. Make split that path into multiple
   targets. The command-generated scratch file/directory were inspected and
   removed. The tracked kiosk launcher binary remains byte-identical to the
   pre-execution snapshot. Subsequent builds used a no-space, unique external
   output path.

## Validation matrix

| Check | Status | Observed result |
|---|---|---|
| WSL sequential startup after Ubuntu distro restart | PASS | `/bin/true` exit 0, no warning |
| C URL validation test | PASS | 22 cases across config and platform validators |
| Chromium policy generator regression in WSL | PASS | 13 assertions |
| P1 source validation | BLOCKED | 41 PASS, 0 FAIL, 1 BLOCKED: `EXAM_URL=NOT_CONFIGURED` |
| Strict native server build | PASS | Full server build with repository warning/error flags |
| All native C/C++ subsystem builds | PASS | Kiosk launcher, agent, proctoring, and server |
| P0 server runtime smoke | PASS (development integration) | 11/11 checks, clean shutdown |
| P2 static artifact audit | PASS (static only) | 49 PASS, 0 FAIL, 0 BLOCKED |
| P2 Chromium policy suite | BLOCKED | 3 static PASS, 0 FAIL, 3 runtime BLOCKED (no Chromium/kiosk) |
| P2 USB policy suite | BLOCKED | 5 PASS, 0 FAIL, 3 BLOCKED (no host USB controllers/daemon; hardware mode disabled) |
| Current image/VM/kiosk acceptance | NOT_RUN | Dirty source, unconfigured exam endpoint; no current candidate image built |
| Mandatory P2 booted-guest matrix | NOT_RUN | No candidate image/guest |
| P3–P7 release phases | BLOCKED / NOT_RUN | See plan prerequisites; no trust authority, consented evaluation, physical evidence, independent assessor, or pilot approval |

The P0 server smoke used an ephemeral loopback port, random test credentials,
and synthetic registry fixtures. It verified service behavior only. It is
not physical TPM, release trust, image boot, or production evidence.

## Evidence locations

- [Phase 1 source and C test logs](../phase1-source-validation-20261018T0320Z/)
- [P0 server runtime smoke](../phase1-source-validation-20261018T0320Z/p0-server-smoke-wsl-retry/)
- [P2 host checks](../phase2-wsl-host-20261018T0930Z/)
- Native binary/build digests are recorded in this run's
  `artifact-sha256.csv`; relevant source hashes are in `source-sha256.csv`.
- Worktree status and command/tool provenance are in `git-status.txt` and
  `run-manifest.txt`.

## Phase disposition

The server and native component build blockers are fixed and verified against
the current dirty working tree. The Phase 1 gate is still **BLOCKED** because
there is no approved configured exam origin, clean immutable candidate build,
current image digest, or boot-to-kiosk acceptance. Phase 2 is still
**BLOCKED** because static checks cannot substitute for runtime enforcement.
Phases 3–7 remain blocked by their external trust, governance, physical-device,
independent-review, and operational prerequisites. No production/release
approval is implied.
