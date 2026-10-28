import urllib.request
import json

BASE = "http://127.0.0.1:8895"

def post_json(path, data, headers=None):
    hdrs = {'Content-Type': 'application/json'}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(f"{BASE}{path}", data=json.dumps(data).encode('utf-8'), headers=hdrs)
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
    req = urllib.request.Request(f"{BASE}{path}", headers=hdrs)
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read().decode('utf-8'))
    except urllib.error.HTTPError as e:
        body = e.read().decode('utf-8')
        try:
            return e.code, json.loads(body)
        except Exception:
            return e.code, {"raw": body}

print("=== 1. Health check ===")
status, health = get_json("/api/v1/health")
print(f"Health: {status} -> {health}")

print("\n=== 2. Admin Login ===")
status, admin_login = post_json("/api/v1/auth/login", {
    "username": "admin",
    "password": "StrongAdminPassword#2026!"
})
print(f"Admin Login: {status} -> {admin_login}")
admin_token = admin_login["token"]

print("\n=== 3. Rejecting unauthorized Exam URL in Backend Config ===")
status, rej = post_json("/api/v1/admin/config", {
    "exam_url": "https://unauthorized-cheating-site.com/hack",
    "exam_name": "Unauthorized Exam",
    "exam_id": "EXAM-HACK-01",
    "allowed_origins": "https://unauthorized-cheating-site.com",
    "exam_duration_minutes": 60
}, headers={"Authorization": f"Bearer {admin_token}"})
print(f"Unauthorized Exam URL attempt (should fail): {status} -> {rej}")

print("\n=== 4. Setting Authorized Exam URL in Backend Config ===")
status, conf = post_json("/api/v1/admin/config", {
    "exam_url": "https://exam.university.edu/session/start",
    "exam_name": "CS401 Distributed Systems Final",
    "exam_id": "EXAM-DEMO-01",
    "allowed_origins": "https://exam.university.edu",
    "exam_duration_minutes": 120
}, headers={"Authorization": f"Bearer {admin_token}"})
print(f"Authorized Exam URL config: {status} -> {conf}")

print("\n=== 5. Verify Kiosk Check-Update reports Authorized Exam ===")
status, kiosk_sync = get_json("/api/v1/kiosk/check-update")
print(f"Kiosk Check-Update: {status} -> {kiosk_sync}")

print("\n=== 6. Test Candidate Authentication (Student CAND-001) ===")
# A. Negative Test: Regular browser (no kiosk headers) -> should be 403 Forbidden
status, neg1 = post_json("/api/v1/candidate/login", {
    "candidate_id": "CAND-001",
    "pin": "123456"
})
print(f"Candidate Login without Kiosk header (should fail 403): {status} -> {neg1}")

# B. Negative Test: Kiosk browser with WRONG PIN -> should be 401 Unauthorized
status, neg2 = post_json("/api/v1/candidate/login", {
    "candidate_id": "CAND-001",
    "pin": "wrong_pin"
}, headers={
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) ExamOS-Kiosk/1.0",
    "X-ExamOS-Kiosk": "1"
})
print(f"Candidate Login with Wrong PIN (should fail 401): {status} -> {neg2}")

# C. Positive Test: Kiosk browser with Valid Student Credentials
status, cand_auth = post_json("/api/v1/candidate/login", {
    "candidate_id": "CAND-001",
    "pin": "123456"
}, headers={
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) ExamOS-Kiosk/1.0",
    "X-ExamOS-Kiosk": "1"
})
print(f"Candidate Login with Valid Credentials: {status} -> {cand_auth}")
