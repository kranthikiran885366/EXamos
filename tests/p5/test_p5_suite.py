#!/usr/bin/env python3
"""
ExamOS Phase 5 — Comprehensive Test & Evidence Suite
tests/p5/test_p5_suite.py

Executes real HTTP requests against live running examos-server on port 9195.
Tests Gates P5-A through P5-I and generates all required JSON/CSV evidence artifacts.
Zero mocks — all tests interact directly with server APIs and real event stores.
"""

import os
import sys
import time
import json
import csv
import math
import hashlib
import urllib.request
import urllib.error
import subprocess
import secrets

SERVER_PORT = int(os.environ.get("EXAMOS_SERVER_PORT", "9195"))
BASE_URL = f"http://127.0.0.1:{SERVER_PORT}"
def required_runtime_token(name):
    value = os.environ.get(name, "")
    if len(value) < 32:
        raise SystemExit(f"{name} must be provided by the live test server (minimum 32 characters)")
    return value

AGENT_TOKEN = required_runtime_token("EXAMOS_AGENT_API_TOKEN")
PROCTOR_TOKEN = required_runtime_token("EXAMOS_PROCTOR_API_TOKEN")
REVIEWER_TOKEN = required_runtime_token("EXAMOS_REVIEWER_TOKEN")
TEST_CANDIDATE_PIN = secrets.token_urlsafe(24)
PRACTICE_CALL_RESULTS = []
WORKSPACE = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
ARTIFACT_DIR = os.environ.get(
    "EXAMOS_P5_ARTIFACT_DIR", os.path.join(WORKSPACE, "artifacts/phase5")
)

os.makedirs(ARTIFACT_DIR, exist_ok=True)

def http_req(method, endpoint, body=None, headers=None):
    url = f"{BASE_URL}{endpoint}"
    data = json.dumps(body).encode("utf-8") if body is not None else None
    h = {"Content-Type": "application/json"}
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            status = resp.status
            content = resp.read().decode("utf-8")
            try:
                parsed = json.loads(content)
            except Exception:
                parsed = content
            if endpoint == "/api/v1/behaviour/practice":
                PRACTICE_CALL_RESULTS.append((status, parsed))
            return status, parsed
    except urllib.error.HTTPError as e:
        content = e.read().decode("utf-8")
        try:
            parsed = json.loads(content)
        except Exception:
            parsed = content
        if endpoint == "/api/v1/behaviour/practice":
            PRACTICE_CALL_RESULTS.append((e.code, parsed))
        return e.code, parsed
    except Exception as e:
        return 500, {"error": str(e)}

def provision_candidate(candidate_id, pin=TEST_CANDIDATE_PIN):
    store_path = os.environ.get("EXAMOS_CANDIDATE_STORE", "/tmp/examos_test_candidates.conf")
    iterations = 600000
    salt_bytes = os.urandom(32)
    salt_hex = salt_bytes.hex()
    derived = hashlib.pbkdf2_hmac("sha256", pin.encode("utf-8"), salt_bytes, iterations, dklen=32).hex()
    
    # Read existing lines if file exists
    lines = []
    if os.path.exists(store_path):
        with open(store_path, "r", encoding="utf-8") as f:
            lines = [l for l in f.readlines() if not l.startswith(f"{candidate_id}:")]
    lines.append(f"{candidate_id}:{iterations}:{salt_hex}:{derived}\n")
    with open(store_path, "w", encoding="utf-8") as f:
        f.writelines(lines)

def create_candidate_session(candidate_id, pin=TEST_CANDIDATE_PIN):
    provision_candidate(candidate_id, pin)
    status, res = http_req("POST", "/api/v1/candidate/login", {"candidate_id": candidate_id, "pin": pin})
    if status == 200 and isinstance(res, dict) and "token" in res:
        token = res["token"]
        http_req("POST", "/api/v1/consent", {"session_id": token, "candidate_id": candidate_id, "consent": True},
                 {"Authorization": f"Bearer {token}"})
        return token
    return None

def candidate_headers(token):
    return {"Authorization": f"Bearer {token}"}

def submit_behaviour_event(token, exam_id, question_id=1, **overrides):
    event = {
        "exam_id": exam_id,
        "question_id": question_id,
        "question_presented_ts": 1000,
        "first_input_ts": 5000,
        "answer_submitted_ts": 35000,
        "question_char_length": 120,
        "edit_count": 3,
        "typing_intervals": [130, 140, 135, 145, 150],
        "focus_fraction": 0.96,
        "gaze_fraction": 0.92,
        "gaze_confidence_pct": 92,
        "camera_available": 1,
        "question_score": 3.0,
        "question_max_marks": 3,
    }
    event.update(overrides)
    return http_req(
        "POST",
        "/api/v1/behaviour/events",
        event,
        candidate_headers(token),
    )

def test_p5_a_baseline(results):
    print("\n--- Gate P5-A: Personal Practice Baselines ---")
    candidate_id = "CAND-BASE-01"
    
    # E2E-1: Insufficient history (only 4 practice quizzes)
    initial_practice_call_count = len(PRACTICE_CALL_RESULTS)
    practice_events_ok = True
    for i in range(1, 5):
        token = create_candidate_session(candidate_id)
        if token:
            event_status, _ = submit_behaviour_event(token, f"PRACTICE-BASE-{i}")
            practice_events_ok = practice_events_ok and event_status == 201
            http_req("POST", "/api/v1/behaviour/practice", {
                "candidate_id": candidate_id,
                "practice_session_id": token
            }, {"Authorization": f"Bearer {token}"})
    
    first_practice_results = PRACTICE_CALL_RESULTS[initial_practice_call_count:]
    practice_completions_ok = (
        len(first_practice_results) == 4 and
        all(status == 201 for status, _ in first_practice_results)
    )
    practice_rejection_reasons = [
        response.get("reason", f"HTTP_{status}")
        for status, response in first_practice_results if status != 201
    ]
    st_inadequate, res_inadequate = http_req(
        "GET",
        f"/api/v1/behaviour/baseline?candidate_id={candidate_id}",
        headers=candidate_headers(token),
    )
    insufficient_handled = (practice_events_ok and practice_completions_ok and st_inadequate == 200 and
                            res_inadequate.get("baseline_status") == "BASELINE_INSUFFICIENT" and
                            res_inadequate.get("eligible_practice_count") == 4)
    print(f"  [P5-A1] Practice accepted: {practice_completions_ok}; "
          f"baseline insufficient correctly handled: {insufficient_handled}; "
          f"rejections={practice_rejection_reasons}")

    # E2E-2: Complete 5th quiz with valid telemetry
    token5 = create_candidate_session(candidate_id)
    fifth_call_start = len(PRACTICE_CALL_RESULTS)
    fifth_event_status, fifth_event_result = submit_behaviour_event(token5, "PRACTICE-BASE-5")
    http_req("POST", "/api/v1/behaviour/practice", {
        "candidate_id": candidate_id,
        "practice_session_id": token5
    }, {"Authorization": f"Bearer {token5}"})
    
    fifth_practice_results = PRACTICE_CALL_RESULTS[fifth_call_start:]
    fifth_practice_status = fifth_practice_results[0][0] if fifth_practice_results else 0
    fifth_practice_result = fifth_practice_results[0][1] if fifth_practice_results else {}
    for pi in range(1, 2):
        tok = token5
        for q in range(1, 4):
            http_req("POST", "/api/v1/behaviour/events", {
                "exam_id": f"PRACTICE-EXAM-{pi}",
                "question_id": q,
                "question_presented_ts": 10000,
                "first_input_ts": 14000 + pi*100,
                "answer_submitted_ts": 40000 + pi*500,
                "question_char_length": 150,
                "edit_count": 3 + (pi % 2),
                "typing_intervals": [120, 130, 125, 140, 115, 135],
                "focus_fraction": 0.98,
                "gaze_fraction": 0.95,
                "gaze_confidence_pct": 95,
                "camera_available": 1,
                "question_score": 3.0,
                "question_max_marks": 3,
                "source_event_range": f"p{pi}-q{q}"
            }, {"Authorization": f"Bearer {tok}"})

    st_ok, res_ok = http_req(
        "GET",
        f"/api/v1/behaviour/baseline?candidate_id={candidate_id}",
        headers=candidate_headers(token5),
    )
    baseline_ok = (st_ok == 200 and fifth_event_status == 201 and
                   fifth_practice_status == 201 and
                   res_ok.get("baseline_status") == "OK" and
                   res_ok.get("eligible_practice_count") >= 5)
    f1_med = res_ok.get("features", {}).get("f1", {}).get("median_ms", 0)
    print(f"  [P5-A2] 5 Quizzes -> Baseline OK: {baseline_ok} (F1 Median: {f1_med}ms)")
    
    passed = insufficient_handled and baseline_ok
    results["P5-A"] = {
        "gate": "Gate P5-A — Personal Practice Baselines",
        "status": "PASS" if passed else "FAIL",
        "insufficient_handled": insufficient_handled,
        "baseline_constructed": baseline_ok,
        "fifth_practice_event_status": fifth_event_status,
        "fifth_practice_status": fifth_practice_status,
        "first_practice_rejections": practice_rejection_reasons,
        "fifth_practice_rejection": fifth_practice_result.get("reason"),
        "fifth_event_error": fifth_event_result.get("error") if isinstance(fifth_event_result, dict) else None,
        "eligible_practice_count": res_ok.get("eligible_practice_count", 0),
        "f1_median_ms": f1_med
    }

def test_p5_b_relay_pattern(results):
    print("\n--- Gate P5-B: Synthetic Relay Pattern Detection ---")
    candidate_id = "CAND-RELAY-01"
    baseline_call_start = len(PRACTICE_CALL_RESULTS)
    
    # 1. Establish baseline
    for i in range(1, 6):
        tok = create_candidate_session(candidate_id)
        practice_event_status, _ = submit_behaviour_event(tok, f"PRACTICE-EXAM-{i}")
        http_req("POST", "/api/v1/behaviour/practice", {
            "candidate_id": candidate_id,
            "practice_session_id": tok
        }, {"Authorization": f"Bearer {tok}"})
        http_req("POST", "/api/v1/behaviour/events", {
            "exam_id": f"PRACTICE-EXAM-{i}",
            "question_id": 1,
            "question_presented_ts": 1000,
            "first_input_ts": 5000,
            "answer_submitted_ts": 30000,
            "question_char_length": 100,
            "edit_count": 4,
            "typing_intervals": [140, 150, 145, 160, 155],
            "focus_fraction": 0.95,
            "gaze_fraction": 0.90,
            "gaze_confidence_pct": 90,
            "camera_available": 1,
            "question_score": 3.0,
            "question_max_marks": 3
        }, {"Authorization": f"Bearer {tok}"})

    baseline_practice_results = PRACTICE_CALL_RESULTS[baseline_call_start:]
    baseline_practices_ok = (
        len(baseline_practice_results) == 5 and
        all(status == 201 for status, _ in baseline_practice_results)
    )
    baseline_practice_rejections = [
        response.get("reason", f"HTTP_{status}")
        for status, response in baseline_practice_results if status != 201
    ]
    baseline_status, baseline = http_req(
        "GET",
        f"/api/v1/behaviour/baseline?candidate_id={candidate_id}",
        headers=candidate_headers(tok),
    )
    baseline_ready = (baseline_practices_ok and baseline_status == 200 and
                      baseline.get("baseline_status") == "OK" and
                      baseline.get("eligible_practice_count", 0) >= 5)

    # 2. Replay Relay Pattern in Exam Session (Long Pause: 130s, Fast Fluent Typing: 40ms inter-key)
    exam_token = create_candidate_session(candidate_id)
    relay_detected = False
    relay_ingestion_ok = True
    for q in range(1, 4):
        st, res = http_req("POST", "/api/v1/behaviour/events", {
            "exam_id": "EXAM-RELAY-TEST",
            "question_id": q,
            "question_presented_ts": 1000,
            "first_input_ts": 135000, # 134s pause (> 120s threshold)
            "answer_submitted_ts": 150000,
            "question_char_length": 100,
            "edit_count": 1,
            "typing_intervals": [35, 40, 38, 42, 36, 45, 39], # Fast burst (< 80ms)
            "focus_fraction": 0.85,
            "gaze_fraction": 0.80,
            "gaze_confidence_pct": 85,
            "camera_available": 1,
            "question_score": 3.0,
            "question_max_marks": 3,
            "source_event_range": f"relay-q{q}"
        }, {"Authorization": f"Bearer {exam_token}"})
        relay_ingestion_ok = relay_ingestion_ok and st == 201
        if res.get("relay_pause") is True and res.get("relay_burst") is True:
            relay_detected = True

    # Compute risk score for relay exam
    st_sc, res_sc = http_req("POST", "/api/v1/behaviour/score/compute", {
        "session_id": exam_token,
        "candidate_id": candidate_id,
        "exam_id": "EXAM-RELAY-TEST"
    })
    relay_flagged = res_sc.get("relay_pattern_flagged") is True
    print(f"  [P5-B] Baseline Ready: {baseline_ready}, Relay Ingested: {relay_ingestion_ok}, "
          f"Pattern Detected: {relay_detected}, Flagged in Score: {relay_flagged}")
    
    passed = baseline_ready and relay_ingestion_ok and relay_detected and relay_flagged
    results["P5-B"] = {
        "gate": "Gate P5-B — Synthetic Relay Pattern Detection",
        "status": "PASS" if passed else "FAIL",
        "baseline_ready": baseline_ready,
        "practice_completions_accepted": baseline_practices_ok,
        "practice_rejections": baseline_practice_rejections,
        "relay_ingestion_ok": relay_ingestion_ok,
        "relay_pause_detected": relay_detected,
        "relay_burst_detected": relay_detected,
        "relay_pattern_flagged": relay_flagged,
        "risk_score": res_sc.get("risk_score", 0)
    }

def test_p5_c_honest_false_flags(results):
    print("\n--- Gate P5-C: Replayed Honest Student False-Flag Rate ---")
    total_honest_sessions = 30
    false_flags = 0
    baseline_failures = 0

    for s in range(1, total_honest_sessions + 1):
        cid = f"HONEST-STUDENT-{s:02d}"
        candidate_practice_call_start = len(PRACTICE_CALL_RESULTS)
        # Seed 5 practice sessions for baseline
        for pi in range(1, 6):
            ptok = create_candidate_session(cid)
            practice_event_status, _ = submit_behaviour_event(
                ptok, f"PRACTICE-HONEST-{s}-{pi}"
            )
            http_req("POST", "/api/v1/behaviour/practice", {
                "candidate_id": cid,
                "practice_session_id": ptok
            }, {"Authorization": f"Bearer {ptok}"})
            http_req("POST", "/api/v1/behaviour/events", {
                "exam_id": f"PRACTICE-EXAM-{pi}",
                "question_id": 1,
                "question_presented_ts": 1000,
                "first_input_ts": 6000 + (s % 5) * 500,
                "answer_submitted_ts": 35000 + (s % 5) * 1000,
                "question_char_length": 120,
                "edit_count": 3,
                "typing_intervals": [130, 140, 135, 145, 150],
                "focus_fraction": 0.96,
                "gaze_fraction": 0.92,
                "gaze_confidence_pct": 92,
                "camera_available": 1,
                "question_score": 3.0,
                "question_max_marks": 3
            }, {"Authorization": f"Bearer {ptok}"})

        candidate_practice_results = PRACTICE_CALL_RESULTS[candidate_practice_call_start:]
        candidate_practice_ok = (
            len(candidate_practice_results) == 5 and
            all(status == 201 for status, _ in candidate_practice_results)
        )
        baseline_status, baseline = http_req(
            "GET",
            f"/api/v1/behaviour/baseline?candidate_id={cid}",
            headers=candidate_headers(ptok),
        )
        if (practice_event_status != 201 or not candidate_practice_ok or baseline_status != 200 or
                baseline.get("baseline_status") != "OK" or
                baseline.get("eligible_practice_count", 0) < 5):
            baseline_failures += 1

        # Honest Exam session
        etok = create_candidate_session(cid)
        for q in range(1, 4):
            http_req("POST", "/api/v1/behaviour/events", {
                "exam_id": "EXAM-HONEST-REPLAY",
                "question_id": q,
                "question_presented_ts": 1000,
                "first_input_ts": 6500 + (s % 5) * 400,
                "answer_submitted_ts": 36000 + (s % 5) * 800,
                "question_char_length": 120,
                "edit_count": 3,
                "typing_intervals": [135, 142, 138, 144, 148],
                "focus_fraction": 0.95,
                "gaze_fraction": 0.91,
                "gaze_confidence_pct": 91,
                "camera_available": 1,
                "question_score": 3.0,
                "question_max_marks": 3
            }, {"Authorization": f"Bearer {etok}"})

        st_sc, res_sc = http_req("POST", "/api/v1/behaviour/score/compute", {
            "session_id": etok,
            "candidate_id": cid,
            "exam_id": "EXAM-HONEST-REPLAY"
        })
        score = res_sc.get("risk_score", 0)
        relay_flag = res_sc.get("relay_pattern_flagged", False)
        if score >= 75 or relay_flag:
            false_flags += 1

    rate_pct = (false_flags / total_honest_sessions) * 100.0
    passed = baseline_failures == 0 and rate_pct < 5.0
    print(f"  [P5-C] Honest Sessions: {total_honest_sessions}, Invalid Baselines: {baseline_failures}, "
          f"False Flags: {false_flags}, Rate: {rate_pct:.2f}% (Target < 5.0%)")
    results["P5-C"] = {
        "gate": "Gate P5-C — Honest Session False-Flag Rate",
        "status": "PASS" if passed else "FAIL",
        "total_sessions": total_honest_sessions,
        "false_flags": false_flags,
        "invalid_baselines": baseline_failures,
        "measured_rate_percent": rate_pct,
        "target_max_percent": 5.0
    }

def test_p5_d_variant_diversity(results):
    print("\n--- Gate P5-D: Individualized Numeric Parameter Diversity ---")
    cohort_size = 20
    candidate_variants = []

    for i in range(1, cohort_size + 1):
        cid = f"CAND-DIVERSE-{i:02d}"
        tok = create_candidate_session(cid)
        st, res = http_req("GET", "/api/v1/exam/variant", headers={"Authorization": f"Bearer {tok}"})
        vid = res.get("variant_id")
        
        # Reviewer endpoint to inspect generated parameters
        st_rev, res_rev = http_req("GET", f"/api/v1/reviewer/variant?variant_id={vid}",
                                   headers={"Authorization": f"Bearer {REVIEWER_TOKEN}"})
        candidate_variants.append(res_rev)

    # Pairwise comparison across all pairs
    total_pairs = 0
    total_param_comparisons = 0
    differing_params = 0
    csv_rows = []

    for i in range(len(candidate_variants)):
        for j in range(i + 1, len(candidate_variants)):
            total_pairs += 1
            v1 = candidate_variants[i]
            v2 = candidate_variants[j]
            
            # Compare question wording
            diff_text = 1 if v1.get("question_text") != v2.get("question_text") else 0
            # Compare answer numeric
            diff_ans = 1 if abs(v1.get("answer_numeric", 0) - v2.get("answer_numeric", 0)) > 1e-4 else 0
            
            differing_params += diff_ans
            total_param_comparisons += 1
            csv_rows.append([
                v1.get("candidate_id"), v2.get("candidate_id"),
                v1.get("variant_id"), v2.get("variant_id"),
                v1.get("answer_numeric"), v2.get("answer_numeric"),
                "DIFFERENT" if diff_ans else "SAME"
            ])

    diversity_rate = (differing_params / total_param_comparisons) * 100.0 if total_param_comparisons > 0 else 0
    passed = diversity_rate >= 95.0
    print(f"  [P5-D] Total Pairs: {total_pairs}, Differing Answers/Params: {differing_params}/{total_param_comparisons}, Diversity: {diversity_rate:.2f}% (Target >= 95.0%)")

    # Export CSV
    csv_path = os.path.join(ARTIFACT_DIR, "variant-diversity.csv")
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Candidate_1", "Candidate_2", "Variant_1", "Variant_2", "Answer_1", "Answer_2", "Comparison"])
        writer.writerows(csv_rows)

    results["P5-D"] = {
        "gate": "Gate P5-D — Individualized Numeric Parameter Diversity",
        "status": "PASS" if passed else "FAIL",
        "cohort_size": cohort_size,
        "total_pairs": total_pairs,
        "differing_parameters": differing_params,
        "total_comparisons": total_param_comparisons,
        "diversity_rate_percent": diversity_rate,
        "target_min_percent": 95.0,
        "csv_artifact": "artifacts/phase5/variant-diversity.csv"
    }

def test_p5_e_watermark_tracing(results):
    print("\n--- Gate P5-E: Visible Watermark Leak Tracing ---")
    candidate_id = "CAND-LEAK-TRACE-01"
    tok = create_candidate_session(candidate_id)
    
    st_var, res_var = http_req("GET", "/api/v1/exam/variant", headers={"Authorization": f"Bearer {tok}"})
    watermark_footer = res_var.get("watermark_footer", "")
    print(f"  [P5-E] Rendered Watermark: '{watermark_footer}'")

    # Extract cropped fragment from simulated leaked screenshot footer
    parts = watermark_footer.split("|")
    fragment = parts[0].strip() if parts else watermark_footer

    # 1. Positive Trace
    st_tr, res_tr = http_req("POST", "/api/v1/reviewer/watermark/trace", {
        "watermark_fragment": fragment
    }, headers={"Authorization": f"Bearer {REVIEWER_TOKEN}"})
    
    positive_match = (st_tr == 200 and res_tr.get("status") == "TRACED")
    traced_ref = res_tr.get("candidate_ref", "")
    print(f"  [P5-E] Positive Trace Result: {positive_match} (Candidate Ref: {traced_ref})")

    # 2. Negative Control (Unrelated / forged fragment)
    st_neg, res_neg = http_req("POST", "/api/v1/reviewer/watermark/trace", {
        "watermark_fragment": "FORGED-NON-EXISTENT-FOOTER"
    }, headers={"Authorization": f"Bearer {REVIEWER_TOKEN}"})
    negative_handled = (st_neg == 404 and res_neg.get("status") == "NOT_TRACED")
    print(f"  [P5-E] Negative Control Handled: {negative_handled}")

    passed = positive_match and negative_handled
    results["P5-E"] = {
        "gate": "Gate P5-E — Visible Watermark Leak Tracing",
        "status": "PASS" if passed else "FAIL",
        "positive_trace_success": positive_match,
        "traced_candidate_ref": traced_ref,
        "negative_control_handled": negative_handled
    }

def test_p5_f_viva_generation(results):
    print("\n--- Gate P5-F: Post-Exam Viva Generation & Validation ---")
    candidate_id = "CAND-VIVA-01"
    tok = create_candidate_session(candidate_id)
    
    submission_receipt = "EXAMOS-SUBMISSION-RECEIPT-HASH-998877665544332211"
    st_viva, res_viva = http_req("POST", "/api/v1/viva/generate", {
        "session_id": tok,
        "candidate_id": candidate_id,
        "exam_id": "EXAM-VIVA-GATE",
        "submission_receipt_hash": submission_receipt
    }, headers={"Authorization": f"Bearer {tok}"})

    viva_id = res_viva.get("viva_id")
    questions = res_viva.get("questions", [])
    q_count = len(questions)
    
    questions_valid = (
        q_count in [2, 3] and
        all(q.get("question_id") and len(q.get("text", "")) >= 20 and
            q.get("assessment_objective") for q in questions)
    )
    viva_success = st_viva == 201 and bool(viva_id) and questions_valid
    provider_unavailable = (
        st_viva == 502 and
        res_viva.get("error") == "VIVA_PROVIDER_UNAVAILABLE"
    )
    print(f"  [P5-F] Viva Generated: {viva_success} (Questions Generated: {q_count}, VivaID: {viva_id})")
    
    for i, q in enumerate(questions):
        print(f"    Q{i+1}: {q.get('text')} [Objective: {q.get('assessment_objective')}]")

    results["P5-F"] = {
        "gate": "Gate P5-F — Post-Exam Viva Generation",
        "status": "PASS" if viva_success else "BLOCKED" if provider_unavailable else "FAIL",
        "reason": "Configured viva provider is unavailable." if provider_unavailable else None,
        "viva_id": viva_id,
        "question_count": q_count,
        "questions": questions
    }
    return viva_id, questions

def test_p5_g_human_review_and_override(viva_id, questions, results):
    print("\n--- Gate P5-G: Human Review, AI Suggestion & Override ---")
    if not viva_id or not questions:
        print("  [P5-G] BLOCKED: no valid viva was generated; dependent review workflow was not exercised.")
        results["P5-G"] = {
            "gate": "Gate P5-G — Human Review and Override",
            "status": "BLOCKED",
            "reason": "A successfully generated viva is required for review workflow validation."
        }
        return

    candidate_id = "CAND-VIVA-01"
    tok = create_candidate_session(candidate_id)

    # 1. Candidate submits response to Viva Question 1
    q1_id = questions[0].get("question_id") if questions else ""
    st_resp, res_resp = http_req("POST", "/api/v1/viva/response", {
        "viva_id": viva_id,
        "question_id": q1_id,
        "response_text": "I chose Floyd's Tortoise and Hare algorithm because it provides O(1) auxiliary space complexity by maintaining two pointers moving at different speeds."
    }, headers={"Authorization": f"Bearer {tok}"})
    
    resp_id = res_resp.get("response_id")
    resp_submitted = (st_resp == 201 and res_resp.get("status") == "SUBMITTED")
    print(f"  [P5-G1] Candidate Viva Response Submitted: {resp_submitted} (RespID: {resp_id})")

    # 2. Reviewer views full evidence
    st_rev, res_rev = http_req("GET", f"/api/v1/reviewer/viva?viva_id={viva_id}",
                               headers={"Authorization": f"Bearer {REVIEWER_TOKEN}"})
    reviewer_view_ok = (st_rev == 200 and res_rev.get("viva_id") == viva_id)

    # 3. AI Suggested Grade
    st_sug, res_sug = http_req("POST", "/api/v1/reviewer/viva/suggest", {
        "viva_id": viva_id,
        "question_id": q1_id,
        "response_id": resp_id
    }, headers={"Authorization": f"Bearer {REVIEWER_TOKEN}"})
    suggested_ok = (st_sug == 200 or st_sug == 201 or res_sug.get("status") in ["SUGGESTED", "UNAVAILABLE"])

    # 4. Human Reviewer Decision / Override with Rationale
    st_dec, res_dec = http_req("POST", "/api/v1/reviewer/viva/decide", {
        "viva_id": viva_id,
        "reviewer_id": "REVIEWER-OFFICER-042",
        "state": 3, # OVERRIDDEN
        "final_score": 0.95,
        "reason_code": "CLEAR_CONCEPTUAL_MASTERY",
        "written_rationale": "Candidate accurately articulated the pointer cycle invariant and verified space complexity constraints."
    }, headers={"Authorization": f"Bearer {REVIEWER_TOKEN}"})
    
    override_ok = (st_dec == 200 and res_dec.get("status") == "DECIDED" and res_dec.get("human_control_verified") is True)
    print(f"  [P5-G2] Human Reviewer Override & Audit: {override_ok} (Final Score: {res_dec.get('final_score')})")

    passed = resp_submitted and reviewer_view_ok and override_ok
    results["P5-G"] = {
        "gate": "Gate P5-G — Human Review and Override Workflow",
        "status": "PASS" if passed else "FAIL",
        "response_submitted": resp_submitted,
        "reviewer_panel_accessed": reviewer_view_ok,
        "human_override_audited": override_ok,
        "final_decision_state": res_dec.get("state", "OVERRIDDEN")
    }

def test_p5_h_security_and_auth(results):
    print("\n--- Gate P5-H: Authorization & Answer-Key Protection ---")
    cand1 = "CAND-AUTH-01"
    cand2 = "CAND-AUTH-02"
    tok1 = create_candidate_session(cand1)
    tok2 = create_candidate_session(cand2)

    # 1. Candidate 2 cannot access Candidate 1's variant answer key
    st_var, res_var = http_req("GET", "/api/v1/exam/variant", headers={"Authorization": f"Bearer {tok1}"})
    vid1 = res_var.get("variant_id")
    
    # Verify candidate response contains NO answer key
    no_answer_key_in_candidate_api = ("answer_numeric" not in res_var and "answer_option_index" not in res_var)
    print(f"  [P5-H1] Candidate API Answer-Key Protected: {no_answer_key_in_candidate_api}")

    # 2. Candidate cannot access reviewer variant endpoint
    st_unauth_rev, _ = http_req("GET", f"/api/v1/reviewer/variant?variant_id={vid1}",
                                headers={"Authorization": f"Bearer {tok2}"})
    reviewer_route_protected = (st_unauth_rev == 401)
    print(f"  [P5-H2] Reviewer Route Unauthorized For Candidate: {reviewer_route_protected}")

    st_unauth_baseline, _ = http_req(
        "GET", f"/api/v1/behaviour/baseline?candidate_id={cand1}"
    )
    st_cross_baseline, _ = http_req(
        "GET",
        f"/api/v1/behaviour/baseline?candidate_id={cand2}",
        headers=candidate_headers(tok1),
    )
    baseline_access_controlled = st_unauth_baseline == 401 and st_cross_baseline == 403

    st_unauth_practice, _ = http_req(
        "POST",
        "/api/v1/behaviour/practice",
        {"candidate_id": cand1, "practice_session_id": tok1},
    )
    practice_access_controlled = st_unauth_practice == 401

    st_unknown_viva_decision, _ = http_req(
        "POST",
        "/api/v1/reviewer/viva/decide",
        {
            "viva_id": "NONEXISTENT-VIVA-ID",
            "reviewer_id": "REVIEWER-OFFICER-042",
            "state": 3,
            "final_score": 0.95,
            "reason_code": "INVALID_VIVA_CONTROL",
            "written_rationale": "This decision must not be accepted without a valid viva record."
        },
        headers={"Authorization": f"Bearer {REVIEWER_TOKEN}"},
    )
    unknown_viva_decision_rejected = st_unknown_viva_decision == 400

    # 3. Duplicate Viva Response Rejected (Idempotency / Anti-tamper)
    st_viva, res_viva = http_req("POST", "/api/v1/viva/generate", {
        "session_id": tok1,
        "candidate_id": cand1,
        "exam_id": "EXAM-AUTH-TEST",
        "submission_receipt_hash": "RECEIPT-AUTH-TEST-001"
    }, headers={"Authorization": f"Bearer {tok1}"})
    
    viva_id = res_viva.get("viva_id")
    viva_questions = res_viva.get("questions", [])
    qid = viva_questions[0].get("question_id", "") if viva_questions else ""
    provider_unavailable = (
        st_viva == 502 and
        res_viva.get("error") == "VIVA_PROVIDER_UNAVAILABLE"
    )
    
    st_first, res_first = http_req("POST", "/api/v1/viva/response", {
        "viva_id": viva_id, "question_id": qid, "response_text": "First response"
    }, headers={"Authorization": f"Bearer {tok1}"})

    st_dup, res_dup = http_req("POST", "/api/v1/viva/response", {
        "viva_id": viva_id, "question_id": qid, "response_text": "Mutated response attempt"
    }, headers={"Authorization": f"Bearer {tok1}"})
    first_response_accepted = (st_first == 201 and res_first.get("status") == "SUBMITTED")
    duplicate_rejected = first_response_accepted and st_dup == 409
    print(f"  [P5-H3] First response accepted: {first_response_accepted}, "
          f"duplicate rejected: {duplicate_rejected} (duplicate HTTP={st_dup})")

    independent_controls_passed = (
        no_answer_key_in_candidate_api and reviewer_route_protected and
        baseline_access_controlled and practice_access_controlled and
        unknown_viva_decision_rejected
    )
    passed = independent_controls_passed and duplicate_rejected
    blocked = provider_unavailable and independent_controls_passed
    results["P5-H"] = {
        "gate": "Gate P5-H — Authorization & Privacy Protection",
        "status": "PASS" if passed else "BLOCKED" if blocked else "FAIL",
        "reason": "Duplicate-response validation requires the unavailable viva provider." if blocked else None,
        "answer_keys_isolated": no_answer_key_in_candidate_api,
        "reviewer_access_controlled": reviewer_route_protected,
        "baseline_access_controlled": baseline_access_controlled,
        "practice_access_controlled": practice_access_controlled,
        "unknown_viva_decision_rejected": unknown_viva_decision_rejected,
        "first_response_accepted": first_response_accepted,
        "duplicate_http_status": st_dup,
        "mutation_rejected": duplicate_rejected
    }

def main():
    print("============================================================")
    print("ExamOS Phase 5 — Full Test & Acceptance Suite")
    print(f"Target Server: {BASE_URL}")
    print("============================================================")

    # Health check
    st, health = http_req("GET", "/api/v1/health")
    if st != 200:
        print(f"FATAL: Server not reachable at {BASE_URL}")
        sys.exit(1)
    print(f"[HEALTH] Server Online: {health}")

    results = {}
    test_p5_a_baseline(results)
    test_p5_b_relay_pattern(results)
    test_p5_c_honest_false_flags(results)
    test_p5_d_variant_diversity(results)
    test_p5_e_watermark_tracing(results)
    viva_id, questions = test_p5_f_viva_generation(results)
    test_p5_g_human_review_and_override(viva_id, questions, results)
    test_p5_h_security_and_auth(results)

    # P5 is not releasable unless fresh P0-P4 gate evidence is independently
    # supplied and validated. This suite cannot infer those results.
    results["P5-I"] = {
        "gate": "Gate P5-I — P0–P4 Regression Verification",
        "status": "BLOCKED",
        "reason": "Fresh, commit-bound P0-P4 gate evidence was not supplied and verified.",
        "P0": "BLOCKED",
        "P1": "BLOCKED",
        "P2": "BLOCKED",
        "P3": "BLOCKED",
        "P4": "BLOCKED"
    }

    # Write JSON evidence files
    for gate_key, data in results.items():
        fname = f"{gate_key.lower().replace('-', '_')}_results.json"
        with open(os.path.join(ARTIFACT_DIR, fname), "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    statuses = [v.get("status", "FAIL") for v in results.values()]
    overall = "FAIL" if "FAIL" in statuses else "BLOCKED" if "BLOCKED" in statuses else (
        "PASS" if statuses and all(status == "PASS" for status in statuses) else "NOT_RUN"
    )

    with open(os.path.join(ARTIFACT_DIR, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump({
            "phase": "P5",
            "execution_ts": int(time.time()),
            "server_url": BASE_URL,
            "overall": overall,
            "gates": results
        }, f, indent=2)

    # Print summary
    print("\n============================================================")
    print("PHASE 5 ACCEPTANCE GATE SUMMARY")
    print("============================================================")
    for k, v in results.items():
        status = v.get("status", "FAIL")
        print(f"[{status}] {v.get('gate', k)}")

    print(f"\nOVERALL PHASE 5 GATE STATUS: {overall}")
    return 0 if overall == "PASS" else 2 if overall == "BLOCKED" else 1

if __name__ == "__main__":
    sys.exit(main())
