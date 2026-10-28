#!/usr/bin/env python3
"""
Phase 3 — Examination Workflow Verification Suite
Validates:
1. Backend connectivity, liveness, and readiness.
2. Candidate authentication (positive, negative, and security header enforcement).
3. Authorized exam assignment receipt & kiosk dispatch synchronization.
4. Launch of configured authorized exam URL in Kiosk Supervisor.
5. Strict blocking of unauthorized URLs across Backend, Supervisor, and Chromium Policy.
"""

import sys
import json
import urllib.request
import urllib.error
import subprocess
import time

BASE_URL = "http://127.0.0.1:8895"
LAUNCHER_BIN = "/mnt/d/SEB BRO/kiosk/launcher/examos-kiosk-launcher"
GEN_POLICY_SCRIPT = "/mnt/d/SEB BRO/image/overlay/usr/local/sbin/generate-chromium-policy.sh"

def log_test(step_num, title):
    print(f"\n{'='*70}\n[STEP {step_num}] {title}\n{'='*70}")

def post_json(path, data, headers=None):
    hdrs = {'Content-Type': 'application/json'}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(f"{BASE_URL}{path}", data=json.dumps(data).encode('utf-8'), headers=hdrs)
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read().decode('utf-8'))
    except urllib.error.HTTPError as e:
        body = e.read().decode('utf-8')
        try:
            return e.code, json.loads(body)
        except Exception:
            return e.code, {"raw": body}

def get_json(path, headers=None):
    hdrs = {}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(f"{BASE_URL}{path}", headers=hdrs)
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read().decode('utf-8'))
    except urllib.error.HTTPError as e:
        body = e.read().decode('utf-8')
        try:
            return e.code, json.loads(body)
        except Exception:
            return e.code, {"raw": body}

def main():
    passed = 0
    total = 0

    # -------------------------------------------------------------------------
    # STEP 1: Connect to Test Backend & Health Check
    # -------------------------------------------------------------------------
    log_test(1, "Connect to Test Backend & Validate Health Status")
    total += 1
    status, health = get_json("/api/v1/health")
    print(f"Status Code: {status}")
    print(f"Response: {json.dumps(health, indent=2)}")
    assert status == 200, f"Expected 200, got {status}"
    assert health.get("liveness") == "LIVE", "Backend is not LIVE"
    assert health.get("readiness") == "READY", "Backend is not READY"
    assert health.get("database") is True, "Database is not connected"
    assert health.get("ledger_integrity") == "INTACT", "Ledger integrity compromised"
    print("✔ [PASS] Test backend is live, ready, and connected to PostgreSQL.")
    passed += 1

    # -------------------------------------------------------------------------
    # STEP 2: Authenticate Admin & Set Authorized Exam Assignment
    # -------------------------------------------------------------------------
    log_test(2, "Authenticate Administrator & Set Authorized Exam Assignment")
    total += 1
    status, admin_resp = post_json("/api/v1/auth/login", {
        "username": "admin",
        "password": "StrongAdminPassword#2026!"
    })
    print(f"Admin Login: {status} -> {admin_resp.get('status')}")
    assert status == 200 and admin_resp.get("status") == "AUTHENTICATED"
    admin_token = admin_resp["token"]
    print(f"Admin Token obtained: {admin_token[:20]}...")

    authorized_exam = {
        "exam_url": "https://exam.university.edu/session/start",
        "exam_name": "CS401 Distributed Systems Final Examination",
        "exam_id": "EXAM-DEMO-01",
        "allowed_origins": "https://exam.university.edu",
        "exam_duration_minutes": 120
    }
    status, conf_resp = post_json("/api/v1/admin/config", authorized_exam, headers={
        "Authorization": f"Bearer {admin_token}"
    })
    print(f"Configuring Authorized Exam: {status} -> {conf_resp}")
    assert status == 200 and conf_resp.get("status") == "SAVED"
    print("✔ [PASS] Authorized exam URL successfully registered in backend.")
    passed += 1

    # -------------------------------------------------------------------------
    # STEP 3: Authenticate Test Student (CAND-001)
    # -------------------------------------------------------------------------
    log_test(3, "Authenticate Test Student & Validate Security Controls")
    
    # 3A: External browser rejection
    total += 1
    status, ext_resp = post_json("/api/v1/candidate/login", {
        "candidate_id": "CAND-001",
        "pin": "123456"
    })
    print(f"3A. External Browser Login (no kiosk header): {status} -> {ext_resp.get('error')}")
    assert status == 403, f"Expected 403, got {status}"
    assert "ACCESS_DENIED" in ext_resp.get("error", "")
    print("✔ [PASS] Non-kiosk browsers are rejected with 403 Forbidden.")
    passed += 1

    # 3B: Bad PIN rejection
    total += 1
    status, bad_pin_resp = post_json("/api/v1/candidate/login", {
        "candidate_id": "CAND-001",
        "pin": "999999"
    }, headers={
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) ExamOS-Kiosk/1.0",
        "X-ExamOS-Kiosk": "1"
    })
    print(f"3B. Invalid PIN Login: {status} -> {bad_pin_resp.get('error')}")
    assert status == 401, f"Expected 401, got {status}"
    print("✔ [PASS] Invalid PIN credentials rejected with 401 Unauthorized.")
    passed += 1

    # 3C: Valid Student Authentication
    total += 1
    status, cand_resp = post_json("/api/v1/candidate/login", {
        "candidate_id": "CAND-001",
        "pin": "123456"
    }, headers={
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) ExamOS-Kiosk/1.0",
        "X-ExamOS-Kiosk": "1"
    })
    print(f"3C. Valid Candidate Login: {status} -> {json.dumps(cand_resp, indent=2)}")
    assert status == 200 and cand_resp.get("status") == "SUCCESS"
    assert cand_resp.get("candidate_id") == "cnd_001" or cand_resp.get("candidate_id") == "CAND-001"
    assert cand_resp.get("name") == "Aarav Sharma"
    print("✔ [PASS] Test student authenticated successfully and received candidate token.")
    passed += 1

    # -------------------------------------------------------------------------
    # STEP 4: Receive Authorized Exam Assignment via Kiosk Synchronization
    # -------------------------------------------------------------------------
    log_test(4, "Receive Authorized Exam Assignment via Kiosk Dynamic Sync")
    total += 1
    status, sync_resp = get_json("/api/v1/kiosk/check-update")
    print(f"Kiosk Check-Update: {status} -> {json.dumps(sync_resp, indent=2)}")
    assert status == 200
    assert sync_resp.get("exam_configured") is True
    assert sync_resp.get("exam_url") == "https://exam.university.edu/session/start"
    assert sync_resp.get("command") == "DISPATCH"
    print("✔ [PASS] Kiosk received authorized exam assignment with command DISPATCH.")
    passed += 1

    # -------------------------------------------------------------------------
    # STEP 5: Launch Authorized Exam URL in Kiosk Supervisor
    # -------------------------------------------------------------------------
    log_test(5, "Launch Authorized Exam URL in Kiosk Supervisor")
    total += 1
    proc = subprocess.Popen([LAUNCHER_BIN], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    time.sleep(1.5)
    proc.terminate()
    try:
        _, err = proc.communicate(timeout=2)
    except:
        proc.kill()
        _, err = proc.communicate()
    print("Supervisor Log Output:")
    print(err)
    assert "Target exam URL: https://exam.university.edu/session/start" in err, "Supervisor did not target the configured URL"
    assert "Created ephemeral browser profile in RAM" in err, "Profile was not created"
    print("✔ [PASS] Kiosk supervisor validated configuration and launched authorized exam URL.")
    passed += 1

    # -------------------------------------------------------------------------
    # STEP 6: Verify Strict Blocking of Unauthorized URLs
    # -------------------------------------------------------------------------
    log_test(6, "Verify Blocking of Unauthorized URLs (3 Independent Defense Layers)")

    # Layer 1: Backend Config API Rejection
    total += 1
    status, rej_url = post_json("/api/v1/admin/config", {
        "exam_url": "https://unauthorized-cheat.net/exam",
        "exam_name": "Cheating Portal",
        "exam_id": "EXAM-CHEAT",
        "allowed_origins": "https://unauthorized-cheat.net",
        "exam_duration_minutes": 60
    }, headers={"Authorization": f"Bearer {admin_token}"})
    print(f"Layer 1 - Backend Config Rejection: {status} -> {rej_url}")
    assert status == 400, f"Expected 400 for unapproved host, got {status}"
    print("✔ [PASS] Backend API rejects unapproved hostnames.")
    passed += 1

    # Layer 2: Native Kiosk Supervisor CLI Validation Rejection
    total += 1
    unauthorized_targets = [
        "https://google.com",
        "https://chatgpt.com",
        "file:///etc/shadow",
        "http://insecure-http.com",
        "javascript:alert(document.cookie)"
    ]
    for url in unauthorized_targets:
        res = subprocess.run([LAUNCHER_BIN, url], capture_output=True, text=True)
        assert res.returncode != 0, f"Supervisor unexpectedly allowed {url}"
        assert "refusing to launch" in res.stderr
        print(f"Layer 2 - Supervisor CLI blocked: {url} (code={res.returncode})")
    print("✔ [PASS] Native kiosk supervisor blocks all unauthorized URLs from launching.")
    passed += 1

    # Layer 3: Chromium Managed Enterprise Policy Enforcement
    total += 1
    policy_proc = subprocess.run(["bash", GEN_POLICY_SCRIPT, "--dry-run"], capture_output=True, text=True)
    assert policy_proc.returncode == 0, f"Failed to generate Chromium policy: {policy_proc.stderr}"
    policy_json = json.loads(policy_proc.stdout)
    
    print("Layer 3 - Chromium Policy Configuration:")
    print(f"  URLBlocklist: {policy_json.get('URLBlocklist')}")
    print(f"  URLAllowlist: {policy_json.get('URLAllowlist')}")
    assert "*" in policy_json.get("URLBlocklist", []), "Wildcard '*' must be in URLBlocklist"
    assert "https://exam.university.edu/*" in policy_json.get("URLAllowlist", []), "Exam URL not in allowlist"
    assert "https://google.com" not in policy_json.get("URLAllowlist", []), "Unauthorized URL leaked into allowlist"
    print("✔ [PASS] Chromium managed policy strictly enforces wildcard blocklist '*' with singular authorized exam allowlist.")
    passed += 1

    # -------------------------------------------------------------------------
    # SUMMARY
    # -------------------------------------------------------------------------
    print("\n" + "="*70)
    print(f"PHASE 3 EXAMINATION WORKFLOW VERIFICATION: {passed}/{total} TESTS PASSED")
    print("="*70)

if __name__ == "__main__":
    main()
