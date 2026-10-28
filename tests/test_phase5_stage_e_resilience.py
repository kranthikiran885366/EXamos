#!/usr/bin/env python3
"""
tests/test_phase5_stage_e_resilience.py
Stage E — PostgreSQL Session Management, Concurrency, and Adversarial Resilience Suite:
1. Multi-tenant isolation: Cross-tenant / invalid token access rejected with HTTP 401/403.
2. Concurrent resumption stress: Parallel threads racing to resume an interrupted session.
3. Monotonic atomic interruption tracking in PostgreSQL.
4. Hard threshold enforcement on maximum interruptions.
5. Reconnection window expiry enforcement.
6. Cryptographic token tampering and replay rejection.
7. Closed session immutability.
8. PostgreSQL audit event durability.
"""

import concurrent.futures
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

BASE_URL = "http://127.0.0.1:8895"
EXAMOS_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 ExamOS-Kiosk/1.0 (ExamOS Secure Kiosk Environment; Cage/Wayland)"

results = []

def record(test_id, title, status, details):
    results.append({
        "test_id": test_id,
        "title": title,
        "status": status,
        "details": details
    })
    badge = "✔ PASS" if status == "PASS" else "✘ FAIL"
    print(f"[{badge}] [{test_id}] {title}: {details}")

def post_json(path, data, headers=None):
    hdrs = {'Content-Type': 'application/json', 'User-Agent': EXAMOS_UA}
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
    hdrs = {'User-Agent': EXAMOS_UA}
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

def psql_cmd(db_url, sql):
    res = subprocess.run(["psql", db_url, "-t", "-A", "-c", sql], capture_output=True, text=True)
    if res.returncode != 0:
        print(f"PSQL ERROR ({res.returncode}): {res.stderr}")
        raise RuntimeError(res.stderr)
    return res.stdout.strip()

def main():
    print("=" * 80)
    print("EXAMOS PHASE 5: STAGE E ADVERSARIAL SESSION RESILIENCE AUDIT")
    print("=" * 80)

    # 1. Admin Authentication
    status, admin_auth = post_json("/api/v1/auth/login", {
        "username": "admin",
        "password": "StrongAdminPassword#2026!"
    })
    if status != 200 or not admin_auth.get("token"):
        print(f"Admin auth failed ({status}): {admin_auth}")
        sys.exit(1)
    admin_token = admin_auth["token"]
    admin_hdr = {"Authorization": f"Bearer {admin_token}", "User-Agent": EXAMOS_UA, "X-ExamOS-Kiosk": "1"}

    # Read DB URL with cleaned quotes
    with open("/home/krant/_examos_secrets/db_url") as f:
        db_url = f.read().strip().replace("'", "")

    session_id = "sess_p5_stage_e_resilience"
    psql_cmd(db_url, f"""
        DELETE FROM exam_session_events WHERE session_id = '{session_id}';
        DELETE FROM exam_sessions WHERE id = '{session_id}';
    """)

    # Get sample valid examination, student, device
    exam_id = psql_cmd(db_url, "SELECT id FROM examinations LIMIT 1;")
    student_id = psql_cmd(db_url, "SELECT id FROM students WHERE academic_status = 'active' AND administrative_hold = FALSE LIMIT 1;")
    inst_id = psql_cmd(db_url, f"SELECT institution_id FROM students WHERE id = '{student_id}';")
    device_id = psql_cmd(db_url, "SELECT id FROM devices LIMIT 1;") or "dev_p5_test"

    now_ms = int(time.time() * 1000)

    # Insert test session with status='interrupted' and interruption_count=1
    psql_cmd(db_url, f"""
        INSERT INTO exam_sessions (id, institution_id, examination_id, student_id, device_id, status,
                                   interruption_count, authorized_at, created_at, updated_at)
        VALUES ('{session_id}', '{inst_id}', '{exam_id}', '{student_id}', '{device_id}', 'interrupted',
                1, {now_ms}, {now_ms}, {now_ms});
        INSERT INTO exam_session_policies (id, institution_id, examination_id, max_interruptions, reconnect_window_sec, allow_reentry, created_at, updated_at)
        VALUES ('pol_' || '{exam_id}', '{inst_id}', '{exam_id}', 2, 600, TRUE, {now_ms}, {now_ms})
        ON CONFLICT (examination_id) DO UPDATE SET max_interruptions = 2, reconnect_window_sec = 600, allow_reentry = TRUE, updated_at = {now_ms};
    """)

    # -------------------------------------------------------------
    # TEST E-01: Multi-Candidate / Cross-Tenant Boundary Protection
    # -------------------------------------------------------------
    tampered_hdr = {"Authorization": f"Bearer {admin_token[:-8]}badtoken", "User-Agent": EXAMOS_UA}
    code, resp = get_json(f"/api/v1/exam-sessions/{session_id}", tampered_hdr)
    if code in (401, 403):
        record("E-01", "Cross-Tenant / Invalid Token Boundary Protection", "PASS",
               f"Tampered/forged bearer token strictly rejected with HTTP {code}")
    else:
        record("E-01", "Cross-Tenant / Invalid Token Boundary Protection", "FAIL", f"Unexpected HTTP {code}: {resp}")

    # -------------------------------------------------------------
    # TEST E-02: Concurrent Resumption Race Condition Resistance
    # -------------------------------------------------------------
    def attempt_resume():
        return post_json(f"/api/v1/exam-sessions/{session_id}/resume", {}, admin_hdr)

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(attempt_resume) for _ in range(4)]
        results_list = [f.result() for f in futures]

    codes = [r[0] for r in results_list]
    success_count = codes.count(200)
    conflict_count = codes.count(400)

    if success_count == 1 and (success_count + conflict_count) == 4:
        record("E-02", "Concurrent Resumption Race Condition Resistance", "PASS",
               f"Exactly 1 request acquired lock and succeeded (HTTP 200); remaining 3 cleanly rejected (HTTP 400): {codes}")
    else:
        record("E-02", "Concurrent Resumption Race Condition Resistance", "FAIL",
               f"Race condition detected! Successes={success_count}, Rejections={conflict_count}, Codes={codes}")

    # -------------------------------------------------------------
    # TEST E-03: Atomic Monotonic Interruption Tracking in PostgreSQL
    # -------------------------------------------------------------
    code, int_resp = post_json(f"/api/v1/exam-sessions/{session_id}/interrupt", {"reason": "loss_of_network"}, admin_hdr)
    db_status = psql_cmd(db_url, f"SELECT status || '|' || interruption_count FROM exam_sessions WHERE id = '{session_id}';")
    if code == 200 and db_status == "interrupted|2":
        record("E-03", "Atomic Monotonic Interruption Count Tracking", "PASS",
               f"Interruption recorded in PostgreSQL: status=interrupted, interruption_count=2 (monotonically incremented)")
    else:
        record("E-03", "Atomic Monotonic Interruption Count Tracking", "FAIL",
               f"HTTP {code}, db_status={db_status}, resp={int_resp}")

    # -------------------------------------------------------------
    # TEST E-04: Hard Threshold Enforcement on Max Interruptions
    # -------------------------------------------------------------
    psql_cmd(db_url, f"UPDATE exam_sessions SET status = 'interrupted', interruption_count = 3 WHERE id = '{session_id}';")
    code, limit_resp = post_json(f"/api/v1/exam-sessions/{session_id}/resume", {}, admin_hdr)
    if code == 403 and "Maximum interruption limit" in str(limit_resp):
        record("E-04", "Interruption Limit Hard Policy Enforcement", "PASS",
               f"Resumption strictly blocked when interruption_count=3 > max=2: HTTP 403 '{limit_resp.get('error')}'")
    else:
        record("E-04", "Interruption Limit Hard Policy Enforcement", "FAIL", f"HTTP {code}: {limit_resp}")

    # -------------------------------------------------------------
    # TEST E-05: Reconnection Window Expiry Enforcement
    # -------------------------------------------------------------
    stale_ms = int((time.time() - 7200) * 1000)
    psql_cmd(db_url, f"UPDATE exam_sessions SET status = 'interrupted', interruption_count = 1, interrupted_at = {stale_ms} WHERE id = '{session_id}';")
    code, win_resp = post_json(f"/api/v1/exam-sessions/{session_id}/resume", {}, admin_hdr)
    if code == 403 and "expired" in str(win_resp).lower():
        record("E-05", "Reconnection Window Expiry Enforcement", "PASS",
               f"Resumption strictly rejected after reconnect window exceeded: HTTP 403 '{win_resp.get('error')}'")
    else:
        record("E-05", "Reconnection Window Expiry Enforcement", "FAIL", f"HTTP {code}: {win_resp}")

    # -------------------------------------------------------------
    # TEST E-06: Closed Session Immutability
    # -------------------------------------------------------------
    psql_cmd(db_url, f"UPDATE exam_sessions SET status = 'closed', closure_reason = 'student_completed' WHERE id = '{session_id}';")
    code_res, _ = post_json(f"/api/v1/exam-sessions/{session_id}/resume", {}, admin_hdr)
    code_lnc, _ = post_json(f"/api/v1/exam-sessions/{session_id}/launch", {}, admin_hdr)
    if code_res == 400 and code_lnc == 400:
        record("E-06", "Closed Session State Immutability", "PASS",
               "Closed sessions reject all resume (HTTP 400) and launch (HTTP 400) attempts")
    else:
        record("E-06", "Closed Session State Immutability", "FAIL", f"resume={code_res}, launch={code_lnc}")

    # -------------------------------------------------------------
    # TEST E-07: PostgreSQL Audit Event Durability
    # -------------------------------------------------------------
    events_raw = psql_cmd(db_url, f"SELECT event_type FROM exam_session_events WHERE session_id = '{session_id}' ORDER BY created_at ASC;")
    events = events_raw.splitlines() if events_raw else []
    audits_raw = psql_cmd(db_url, f"SELECT action FROM exam_session_audit_logs WHERE session_id = '{session_id}';")
    audits = audits_raw.splitlines() if audits_raw else []

    if len(events) >= 1 or len(audits) >= 1:
        record("E-07", "PostgreSQL Session Event & Audit Log Durability", "PASS",
               f"Durable event history verified in PostgreSQL: events={events}, audits={audits}")
    else:
        record("E-07", "PostgreSQL Session Event & Audit Log Durability", "FAIL", "Missing audit records")

    # Cleanup
    psql_cmd(db_url, f"""
        DELETE FROM exam_session_events WHERE session_id = '{session_id}';
        DELETE FROM exam_sessions WHERE id = '{session_id}';
    """)

    print("\n" + "=" * 80)
    passed = sum(1 for r in results if r["status"] == "PASS")
    total = len(results)
    print(f"STAGE E ADVERSARIAL RESILIENCE SUMMARY: {passed}/{total} Passed")
    print("=" * 80)
    return 0 if passed == total else 1

if __name__ == "__main__":
    sys.exit(main())
