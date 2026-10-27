# ExamOS Phase 2 host-side static checks

**Run ID:** `phase2-static-host-20261018T0905Z`  
**Source revision:** `c8d8c6149458e9c1611966d5f2db66ed2f42e2d1`  
**Worktree:** Dirty  
**Classification:** Windows Git Bash static/source checks only

## Results

| Check | Status | Result |
|---|---|---|
| P2 static artifact audit (`p2-static-audit.sh`) | PASS (static only) | 49 PASS, 0 FAIL, 0 BLOCKED |
| Chromium policy suite (`p2-chromium-policy-tests.sh`) | BLOCKED | 3 static PASS, 0 FAIL, 3 BLOCKED |
| Chromium policy loaded in running browser | BLOCKED | Chromium binary unavailable |
| Chromium sandbox and active kiosk process | BLOCKED | No running Chromium kiosk process |
| Runtime P2 mandatory matrix | NOT_RUN | No current candidate image or isolated booted guest |
| P0 TPM secret-mapping regression | PASS (static only) | Mapping and VMware builder contracts passed; no TPM operation |

The Chromium static checks confirm the checked-in policy JSON syntax and
selected values, including origin-scoped audio/video entries. The three
blocked checks require a running Chromium installation and guest kiosk.
Static source configuration cannot establish firewall enforcement, AppArmor
enforcement, USB authorization, dm-verity corruption rejection, kernel
hardening, or recovery in a running guest. **Phase 2 remains BLOCKED.**

## Environment and safety

The host has Windows Git Bash, Python 3.11.9, and Docker Desktop installed,
but the Docker daemon is stopped. Ubuntu-26.04 appears as a running WSL
distribution; WSL execution fails with `Wsl/Service/E_UNEXPECTED`, including
as root. No GCC, Clang, QEMU, or Chromium executable is available on the
host. Shared virtualization services were not restarted; no package was
installed and no physical device or firmware was accessed.

All test outputs are in this run's `p2-static-audit/` and
`p2-chromium-policy/` subdirectories. The Python compatibility shim was
temporary and removed after testing.
