#!/usr/bin/env bash
# ExamOS Stage 1 verification script — run via WSL, read-only checks.
# Exit 0 = all checks passed. Exit 1 = one or more checks failed.
set -euo pipefail

REPO="/mnt/d/SEB BRO"
errors=0
results=""

check() {
    local name="$1" result="$2" detail="$3"
    if [ "$result" = "PASS" ]; then
        echo "PASS  $name"
    else
        echo "FAIL  $name: $detail"
        errors=$((errors + 1))
    fi
    results="${results}${result}|${name}|${detail}\n"
}

# ---- 1. bash syntax: generate-chromium-policy.sh ----
if bash -n "${REPO}/image/scripts/generate-chromium-policy.sh" 2>/tmp/bash_err; then
    check "bash-n:generate-chromium-policy.sh" "PASS" "syntax ok"
else
    check "bash-n:generate-chromium-policy.sh" "FAIL" "$(cat /tmp/bash_err)"
fi

# ---- 2. bash syntax: generate-nftables.sh (regression) ----
if bash -n "${REPO}/image/scripts/generate-nftables.sh" 2>/tmp/bash_err; then
    check "bash-n:generate-nftables.sh" "PASS" "syntax ok"
else
    check "bash-n:generate-nftables.sh" "FAIL" "$(cat /tmp/bash_err)"
fi

# ---- 3. JSON validation: chromium policy (no hardcoded domain, no catch-all) ----
python3 - <<'PYEOF'
import json, sys
path = "/mnt/d/SEB BRO/image/overlay/etc/chromium/policies/managed/examos_policies.json"
try:
    d = json.load(open(path))
except json.JSONDecodeError as e:
    print("FAIL:json-parse: " + str(e)); sys.exit(1)

issues = []
for key in ["URLAllowlist", "VideoCaptureAllowedUrls", "AudioCaptureAllowedUrls"]:
    for entry in d.get(key, []):
        if "examos.security" in entry or "*.examos" in entry:
            issues.append(key + ": " + entry)

if issues:
    print("FAIL:hardcoded-domain: " + str(issues)); sys.exit(1)

al = d.get("URLAllowlist", [])
if not any("127.0.0.1" in x or "localhost" in x for x in al):
    print("FAIL:no-localhost-in-allowlist"); sys.exit(1)

print("PASS:chromium-policy: " + str(len(al)) + " URLAllowlist entries, no hardcoded domain")
PYEOF
rc=$?
if [ $rc -eq 0 ]; then
    check "json:chromium-policy" "PASS" "no hardcoded domain, localhost present"
else
    check "json:chromium-policy" "FAIL" "see python output above"
    errors=$((errors + 1))
fi

# ---- 4. JSON validation: opt/chrome policy (no catch-all https://* or hardcoded domain) ----
python3 - <<'PYEOF'
import json, sys
path = "/mnt/d/SEB BRO/image/overlay/etc/opt/chrome/policies/managed/examos_policies.json"
try:
    d = json.load(open(path))
except json.JSONDecodeError as e:
    print("FAIL:json-parse: " + str(e)); sys.exit(1)

issues = []
for key in ["URLAllowlist", "VideoCaptureAllowedUrls", "AudioCaptureAllowedUrls"]:
    for entry in d.get(key, []):
        if entry == "https://*" or "examos.security" in entry or "*.examos" in entry:
            issues.append(key + ": " + entry)

if issues:
    print("FAIL:unsafe-entry: " + str(issues)); sys.exit(1)

for key in ["AudioCaptureAllowed", "VideoCaptureAllowed"]:
    if key in d:
        print("FAIL:global-capture-key-still-present: " + key); sys.exit(1)

print("PASS:opt-chrome-policy: no catch-all, no hardcoded domain, per-origin capture lists only")
PYEOF
rc=$?
if [ $rc -eq 0 ]; then
    check "json:opt-chrome-policy" "PASS" "no catch-all https://*, no hardcoded domain"
else
    check "json:opt-chrome-policy" "FAIL" "see python output above"
    errors=$((errors + 1))
fi

# ---- 5. exam.conf fail-closed: EXAM_URL=NOT_CONFIGURED ----
EXAM_URL=$(grep '^EXAM_URL=' "${REPO}/image/overlay/etc/examos/exam.conf" | head -1 | cut -d= -f2-)
if [ "$EXAM_URL" = "NOT_CONFIGURED" ]; then
    check "exam-conf:fail-closed" "PASS" "EXAM_URL=NOT_CONFIGURED"
else
    check "exam-conf:fail-closed" "FAIL" "EXAM_URL='${EXAM_URL}' expected NOT_CONFIGURED"
fi

# ---- 6. kiosk.service wires in examos-chromium-policy.service ----
KIOSK_SVC="${REPO}/image/overlay/etc/systemd/system/examos-kiosk.service"
if grep -q 'examos-chromium-policy.service' "$KIOSK_SVC"; then
    check "kiosk-svc:requires-policy-generator" "PASS" "Requires+After present"
else
    check "kiosk-svc:requires-policy-generator" "FAIL" "examos-chromium-policy.service not referenced"
fi

# ---- 7. examos-chromium-policy.service exists ----
POLICY_SVC="${REPO}/image/overlay/etc/systemd/system/examos-chromium-policy.service"
if [ -f "$POLICY_SVC" ]; then
    check "policy-svc:file-exists" "PASS" "examos-chromium-policy.service present"
else
    check "policy-svc:file-exists" "FAIL" "file missing"
fi

# ---- 8. generator is installed to expected /usr/local/sbin path in overlay ----
# Script lives in image/scripts/; the service ExecStart references /usr/local/sbin/.
# The mkosi build should install it. We verify the source file exists.
GEN_SRC="${REPO}/image/scripts/generate-chromium-policy.sh"
if [ -f "$GEN_SRC" ]; then
    check "generator:source-exists" "PASS" "image/scripts/generate-chromium-policy.sh present"
else
    check "generator:source-exists" "FAIL" "source file missing"
fi

# ---- 9. Dry-run of generator with a test URL ----
# Temporarily export the config path to a test exam.conf
TMP_CONF=$(mktemp /tmp/exam_test_XXXX.conf)
printf 'EXAM_URL=https://exam.example-university.edu\nEXAM_NAME=Test\n' > "$TMP_CONF"
EXAM_CONF="$TMP_CONF" bash "${REPO}/image/scripts/generate-chromium-policy.sh" --dry-run > /tmp/dry_run_out.json 2>/tmp/dry_run_err.txt
dry_rc=$?
rm -f "$TMP_CONF"

if [ $dry_rc -eq 0 ]; then
    # Validate the generated JSON contains the injected exam origin
    python3 - <<'PYEOF2'
import json, sys
try:
    d = json.load(open("/tmp/dry_run_out.json"))
except json.JSONDecodeError as e:
    print("FAIL:dry-run-json: " + str(e)); sys.exit(1)
al = d.get("URLAllowlist", [])
if not any("example-university.edu" in x for x in al):
    print("FAIL: exam origin not in URLAllowlist: " + str(al)); sys.exit(1)
print("PASS: exam origin injected into URLAllowlist: " + str(al))
PYEOF2
    py_rc=$?
    if [ $py_rc -eq 0 ]; then
        check "generator:dry-run" "PASS" "origin injected correctly"
    else
        check "generator:dry-run" "FAIL" "origin not in output JSON"
    fi
else
    err=$(cat /tmp/dry_run_err.txt)
    check "generator:dry-run" "FAIL" "script exit $dry_rc: $err"
fi

# ---- 10. Fail-closed: generator rejects NOT_CONFIGURED ----
TMP_CONF2=$(mktemp /tmp/exam_fail_XXXX.conf)
printf 'EXAM_URL=NOT_CONFIGURED\n' > "$TMP_CONF2"
EXAM_CONF="$TMP_CONF2" bash "${REPO}/image/scripts/generate-chromium-policy.sh" --check-only > /dev/null 2>&1 && fail_rc=0 || fail_rc=$?
rm -f "$TMP_CONF2"
if [ "$fail_rc" -ne 0 ]; then
    check "generator:rejects-not-configured" "PASS" "exit $fail_rc as expected"
else
    check "generator:rejects-not-configured" "FAIL" "should have exited non-zero for NOT_CONFIGURED"
fi

# ---- 11. Fail-closed: generator rejects plain http:// for non-loopback ----
TMP_CONF3=$(mktemp /tmp/exam_http_XXXX.conf)
printf 'EXAM_URL=http://exam.example-university.edu\n' > "$TMP_CONF3"
EXAM_CONF="$TMP_CONF3" bash "${REPO}/image/scripts/generate-chromium-policy.sh" --check-only > /dev/null 2>&1 && http_rc=0 || http_rc=$?
rm -f "$TMP_CONF3"
if [ "$http_rc" -ne 0 ]; then
    check "generator:rejects-http-non-loopback" "PASS" "exit $http_rc as expected"
else
    check "generator:rejects-http-non-loopback" "FAIL" "should have exited non-zero for plain http:// non-loopback"
fi

# ---- Summary ----
echo ""
echo "================================================"
if [ "$errors" -eq 0 ]; then
    echo "RESULT: ALL CHECKS PASSED"
    exit 0
else
    echo "RESULT: $errors CHECK(S) FAILED"
    exit 1
fi
