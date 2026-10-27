# Phase 0 reconciliation addendum

**Captured:** 2026-10-18  
**Source revision:** `c8d8c6149458e9c1611966d5f2db66ed2f42e2d1`  
**Branch:** `work/p0-secure-release-remediation-20261011`  
**Worktree:** Dirty  
**Classification:** Development inventory; not release evidence

## Baseline result

The external snapshot at `D:\SEB BRO-execution-backup-20261018-0847.zip`
has SHA-256
`9ffe313c3a24aac17e62b34e5738877fdf5a2d04243439ec4ea9dac38de942c7`;
ZIP CRC validation passed. It contains 725 entries, including two WSL
symlinks recorded as link metadata. Four absent tracked paths are recorded
in the archive sidecar as already deleted at capture time. Ignored outputs
were inventoried separately and were not included in the archive.

The initial inventory has the full Git status, 115 ignored paths, 218
artifact hashes, tool versions, and a source-tree manifest digest. The
[artifact evidence index](artifact-evidence-index.csv) binds those artifact
hashes to the source revision and dirty state. Per-item evidence class and
current gate status are `UNKNOWN`: they cannot safely be inferred from a
filename or digest alone.

**Phase 0 disposition: PARTIAL; exit criteria not met.** The source snapshot
and inventory are captured, but the evidence set is not fully classified or
re-bound to fresh gates. The four deleted paths and unknown evidence classes
must remain visible; no old PASS is promoted.

## Phase status reconciliation

The repository's detailed audit snapshot is dated 2026-10-12. Treat its
artifact statuses as historical until regenerated against a clean identified
source and current artifact digests.

| Plan phase | Latest available evidence | Current disposition |
|---|---|---|
| 0 — Freeze and reconcile | Snapshot and inventory captured in this run; item-level evidence classes remain unknown. | PARTIAL; exit criteria not met |
| 1 — Build and kiosk acceptance | Historical P0/P1 evidence is stale or failing. Fresh source validation: 41 PASS, 0 FAIL, 1 BLOCKED because `EXAM_URL=NOT_CONFIGURED`; the exact-origin policy regression passes. | BLOCKED; no current candidate image/boot/kiosk acceptance |
| 2 — Runtime OS lockdown | Historical manifest says 20 mandatory tests are `NOT_RUN`. | BLOCKED; no isolated booted guest or current image binding |
| 3 — Device trust and key release | Historical aggregate P3 is `INVALIDATED`; software-TPM outcomes remain development-only. | BLOCKED; production authority, signed registries, and physical TPM evidence absent |
| 4 — Proctoring and governance | Historical P4 quality result is `INVALIDATED`; synthetic data cannot establish model accuracy. | BLOCKED; approved model, consented representative data, governance, and independent evaluation absent |
| 5 — Candidate workflows and operations | Historical P5-A–E passes are limited to their recorded scope; P5-F–I include blocked gates. | BLOCKED; provider, privacy/review controls, and fresh upstream evidence absent |
| 6 — Independent assessment and pilot | Historical prerequisite audit is `BLOCKED`. | BLOCKED; written authorization, independent assessor, approved hardware, and pilot roles absent |
| 7 — Commercial launch and scaling | The plan identifies revenue/pricing as hypotheses and requires measured pilot and operating evidence. | NOT_RUN / BLOCKED; no approved pilot or measured operating data |

## This execution's Phase 1 source increment

The loopback HTTP exception is now limited to
`http://127.0.0.1:8000` and `http://localhost:8000` in both server URL
validation and Chromium policy generation. Regression cases cover both
allowed forms, missing ports, and non-admin ports.

The Chromium policy generator test passed 13 assertions under Windows Git
Bash with the installed Python runtime. The P1 source validator reported
41 PASS, 0 FAIL, and 1 BLOCKED. These are development/source checks only.
The C URL-validator unit test could not run because GCC/Clang are unavailable
and the WSL Ubuntu invocation failed to start. QEMU is unavailable on the
host, and the configured exam URL remains `NOT_CONFIGURED`.

The full Phase 1 gate is therefore **BLOCKED**, not passed. No image build,
VM boot, P2 runtime, physical-device operation, firmware/TPM/media write,
production trust, privacy approval, or independent assessment was performed.
Later phases remain blocked and were not represented as passes.

The run-specific outputs and hashes are recorded in
[`../phase1-source-validation-20261018T0320Z/`](../phase1-source-validation-20261018T0320Z/).
