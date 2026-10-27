# ExamOS Stage 1 Increment: Dynamic Exam Origin Policy

**Run ID:** `stage1-dynamic-policy-20261018T030000Z`  
**Source revision:** `c8d8c6149458e9c1611966d5f2db66ed2f42e2d1`  
**Branch:** `work/p0-secure-release-remediation-20261011`  
**Worktree:** Dirty; existing user changes preserved.  
**Classification:** Source/unit validation only. No image, VM, hardware, production, or independent-assessment claim.

## Scope and result

The Chromium policy generator previously added wildcard subdomains for a configured exam hostname. A configuration for `https://exam.alpha.edu` therefore also permitted `https://*.exam.alpha.edu`, although no additional origins had been separately reviewed. Server-side configuration validation also used URL-prefix checks, which accepted malformed or lookalike authorities that the kiosk might later reject.

This increment now generates policy entries only for the canonical configured origin plus the two loopback admin origins. URL syntax, hostname labels, ports, userinfo, scheme, and the exact development-only HTTP loopback exception are validated server-side with the existing OpenSSL URL parser and matching kiosk-generator checks. Empty URL remains the fail-closed unconfigured state.

This does **not** implement signed policy distribution, approvals, external-origin review, firewall DNS/IP enforcement, durable transactional config history, RBAC/MFA, or runtime Chromium verification. The full server build and release phases remain blocked; no module or phase is marked complete based on these checks.

## Changed source files

- `image/scripts/generate-chromium-policy.sh`
- `server/admin/config_manager.c`
- `server/include/config_manager.h`
- `server/main.c`
- `tests/p1/chromium-policy-generator-test.sh`
- `tests/server/config-url-validation-test.c`

## Test matrix

| ID | Check | Observed result | Status | Evidence |
| --- | --- | --- | --- | --- |
| DYN-01 | Distinct institution origins, exact-origin allowlist, no implicit wildcard, loopback dev URL, HTTPS enforcement, credentials/port/host validation | 8 generator cases passed | PASS | `chromium-policy-generator-test.log` |
| DYN-02 | Config-manager URL parsing: HTTPS origins, ports, IPv4/localhost dev HTTP, spoofed loopback, external HTTP, userinfo, bad ports/hosts, wildcard and placeholders | 18 cases passed under `-Wall -Wextra -Werror` | PASS | `config-url-validation-test.log` |
| DYN-03 | Existing Stage 1 source verifier and generator dry-run | All checks passed | PASS | `stage1-verify.log` |
| DYN-04 | Changed `server/main.c` translation unit | Strict compile passed | PASS | Command recorded below; object emitted under WSL `/tmp` |
| P1-01 | Repository P1 source validation | 40 checks passed; blocked because `EXAM_URL=NOT_CONFIGURED` | BLOCKED | `p1-source-validation.log` |
| BUILD-01 | Full native server build into isolated WSL `/tmp` | Stopped at `server/admin/enterprise_platform.c:1030`, `-Werror=format-truncation`; this file is outside this change | BLOCKED | `full-server-build.log`; no repository build outputs written |
| IMG-01 | Current image build / boot / kiosk runtime | Not run | NOT_RUN | Requires a clean isolated source and deployment URL/configuration |
| HW-01 | Physical TPM / hardware validation | Not run | BLOCKED | Requires approved physical-device provisioning and evidence plan |

## Commands executed

```text
wsl.exe -d Ubuntu-26.04 -- bash "/mnt/d/SEB BRO/tests/p1/chromium-policy-generator-test.sh"
wsl.exe -d Ubuntu-26.04 -- bash -c "gcc -Wall -Wextra -Werror -I'/mnt/d/SEB BRO/server/include' '/mnt/d/SEB BRO/tests/server/config-url-validation-test.c' '/mnt/d/SEB BRO/server/admin/config_manager.c' -lcrypto -o '/mnt/d/SEB BRO-stage1-pre-edit/config-url-validation-test' && '/mnt/d/SEB BRO-stage1-pre-edit/config-url-validation-test'"
wsl.exe -d Ubuntu-26.04 -- bash -c "gcc -Wall -Wextra -Werror -Wno-error=deprecated-declarations -O2 -I'/mnt/d/SEB BRO/server/include' -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fno-omit-frame-pointer -Wformat=2 -Wformat-security -Wstringop-truncation -Wno-unused-parameter -c '/mnt/d/SEB BRO/server/main.c' -o /tmp/examos-server-main.o"
wsl.exe -d Ubuntu-26.04 -- bash "/mnt/d/SEB BRO/artifacts/evidence/stage0-inspect-20261017-215333/stage1-verify.sh"
wsl.exe -d Ubuntu-26.04 -- bash "/mnt/d/SEB BRO/tests/p1/validate-source.sh"
wsl.exe -d Ubuntu-26.04 -- bash -c "make -C '/mnt/d/SEB BRO/server' BUILD_DIR=/tmp/examos-stage1-server-build-final all"
git diff --check -- image/scripts/generate-chromium-policy.sh server/admin/config_manager.c server/include/config_manager.h server/main.c tests/server/config-url-validation-test.c
```

## Recovery and provenance

A pre-edit external copy of `server/admin/config_manager.c`, `server/include/config_manager.h`, and `server/main.c` is at `D:\SEB BRO-stage1-pre-edit\`; each copy was SHA-256 checked against its source before modification. Manifest SHA-256: `D7F06663856F041886C37BBEF628AF651204FEFF06C3F125D2A6E29D499BC673`. The earlier external archive `D:\SEB BRO-execution-backup-20261017-223617.zip` has SHA-256 `B0A6704743EBCBF85480F60EEFDEE6555746E8D9D0D86DC361665BCA73524D16`; the pre-edit sidecar records matching hashes for its five policy-related sources.

Source SHA-256 values:

- `image/scripts/generate-chromium-policy.sh`: `61D4DC601659D6507C22C4B6C0E7202C37C7784C086023F9E845B3BF645D3A2F`
- `tests/p1/chromium-policy-generator-test.sh`: `CDAF6B6566463932F9C60225259DDB56CECBEF0441293768FCBAB98C5CDD85F9`
- `server/admin/config_manager.c`: `421B9D3D0E4E431C09815B4A07E8D6B768D0945834F040AC38425E206F04D95E`
- `server/include/config_manager.h`: `2F81BB6BEC70DEFAEDEBCD3D37325610D2378110FBB8E58F7A8396A6FD7C0718`
- `server/main.c`: `9DE3C3321327B53DF042E91593A4214C6C1F5FABC7E5812EAB0FF29575B2BFEE`
- `tests/server/config-url-validation-test.c`: `4E15FDD62ACE0EE4C2A59AC9D465551172241914A6FDF40516973D0C3172F85A`

Evidence-log SHA-256 values:

- `chromium-policy-generator-test.log`: `A58161F57128C92A9DA339EA92E1C66A457A0773926C740CF11011F1B344D051`
- `config-url-validation-test.log`: `CAD5D915634DD4B6997C817189B2637C88C4B7D8C7F36282F934F66763D79D20`
- `stage1-verify.log`: `64739742EF73A641CE542FCC94C8400C8D702AE9CFD2634BE9655CAB9463A9CF`
- `p1-source-validation.log`: `9B73504C3AFDC7D4F48DAD262949FF9C94EFA3A89A83D6497C74120F993BBD36`
- `full-server-build.log`: `7C4F36EFD9C53EEA849D607F1116CD322981815F87A0F8AAC3A58EA1AE52DE11`

## Gate decision

**Stage 1 source increment: PASS for the scoped URL-policy and API-validation tests. Full P1 image/kiosk gate: BLOCKED.** No image or release artifact digest applies because no image was built. P0 remains subject to its existing evidence; P2 runtime remains NOT_RUN; P3/P4 remain INVALIDATED; P5/P6 and production remain BLOCKED / NOT APPROVED as recorded in the project audit.
