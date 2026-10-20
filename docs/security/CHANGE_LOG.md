# Security change log

| When | Issue | Change | Test | Evidence |
|------|-------|--------|------|----------|
| 2026-10-11 | — | Preserved `/tmp/examos-p3-results.BToS4h` with SHA-256 | `sha256sum -c MANIFEST.sha256` | `artifacts/p3/evidence-packages/examos-p3-results.BToS4h-20261011T053619Z/` |
| 2026-10-11 | — | Worktree snapshot (status, staged stat, source.diff) | n/a | `artifacts/backups/worktree-20261011T112140Z/` |
| 2026-10-11 | E-01 | Go verifier: empty golden PCR is FAIL; still development-only | rebuild verifier if go present | code |
| 2026-10-11 | E-02 E-03 | Production fail-closed ledger HMAC and session journal | `startup-fail-closed.py` | after run |
| 2026-10-11 | E-04 E-05 E-06 | Suite: HMAC key, session journal, enrolled AK, EK test CA | `attestation-suite.sh` isolated dir | new package; Oct 11 package untouched |
