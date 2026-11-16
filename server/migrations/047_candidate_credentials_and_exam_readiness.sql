-- 047_candidate_credentials_and_exam_readiness.sql
-- Ensure candidate credentials, published institution policies, and active exam schedules
-- are persistently configured for enterprise pilot assessment workflows.

BEGIN;

-- 1. Seed / Publish active kiosk policy for institution SPPIO-QA-1110 (pilot)
INSERT INTO console_records (
    collection,
    record_id,
    institution_id,
    data,
    created_by,
    updated_by,
    created_at,
    updated_at
)
VALUES (
    'policies',
    'pol_5c5b2d6326',
    'ins_1794319503_7dfa',
    '{
        "id": "pol_5c5b2d6326",
        "name": "nqt-secure-kiosk",
        "status": "published",
        "version": 1,
        "tenantId": "ins_1794319503_7dfa",
        "config": {
            "origins": ["https://sppio-os.vercel.app", "https://example.com"],
            "allowUsb": false,
            "requireTpm": true,
            "onViolation": "Isolate device & notify supervisor",
            "kioskLockdown": true
        },
        "hash": "4a7b5d12ef389104",
        "sig": "MEQCIG7182938475a6b7c8d9e0f123456789abcdef0123456789abcdef0123456789AiA9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba",
        "createdAt": 1794335497034,
        "createdBy": "usr_1794319703_1039",
        "publishedAt": 1794812000000,
        "publishedBy": "usr_root"
    }'::jsonb,
    'usr_system',
    'usr_system',
    EXTRACT(EPOCH FROM NOW())::BIGINT * 1000,
    EXTRACT(EPOCH FROM NOW())::BIGINT * 1000
)
ON CONFLICT (collection, record_id) DO UPDATE SET
    data = EXCLUDED.data,
    updated_at = EXCLUDED.updated_at;

-- 2. Update examination QA-RETEST-1110 to scheduled status with published policy and proctor-verify authMode
UPDATE examinations
SET
    status = 'scheduled',
    policy_id = 'pol_5c5b2d6326',
    exam_url = 'https://sppio-os.vercel.app/exam/QA-RETEST-1110',
    allowed_origins = 'https://sppio-os.vercel.app,https://example.com',
    exam_config = jsonb_set(
        jsonb_set(
            jsonb_set(
                jsonb_set(
                    exam_config,
                    '{policyId}',
                    '"pol_5c5b2d6326"'
                ),
                '{authMode}',
                '"proctor-verify"'
            ),
            '{examUrl}',
            '"https://sppio-os.vercel.app/exam/QA-RETEST-1110"'
        ),
        '{origins}',
        '["https://sppio-os.vercel.app", "https://example.com"]'::jsonb
    ),
    updated_at = EXTRACT(EPOCH FROM NOW())::BIGINT * 1000
WHERE id = 'exm_1794324909_9383';

-- 3. Update canonical exams table
UPDATE exams
SET
    status = 'scheduled',
    policy_id = 'pol_5c5b2d6326',
    exam_url = 'https://sppio-os.vercel.app/exam/QA-RETEST-1110',
    auth_mode = 'proctor-verify',
    updated_at = EXTRACT(EPOCH FROM NOW())::BIGINT * 1000
WHERE id = 'exm_1794324909_9383';

-- 4. Extend active examination schedule window (2023 - 2030)
UPDATE exam_schedules
SET
    start_time = 1700000000000,
    end_time = 1900000000000
WHERE exam_id = 'exm_1794324909_9383';

-- 5. Seed credentials and active registration for Candidate Rahul Kumar (QA1110002)
-- PBKDF2-HMAC-SHA256 (210,000 iterations, salt='QA1110002', PIN='948102') -> fbeda51b6ba404e3959af6ecb5aa90ec673a709f47dcf951c2840f681902d43a
UPDATE candidates
SET
    pin_hash = 'fbeda51b6ba404e3959af6ecb5aa90ec673a709f47dcf951c2840f681902d43a',
    status = 'registered',
    identity = 'pending',
    exam_id = 'exm_1794324909_9383',
    center_id = 'ctr_1794324944_0ae60d7c',
    seat = 'A02'
WHERE roll_no = 'QA1110002';

-- 6. Ensure exam assignment and eligibility status
UPDATE exam_student_assignments
SET
    assigned_exam_url = 'https://sppio-os.vercel.app/exam/QA-RETEST-1110',
    eligibility_status = 'eligible',
    assignment_status = 'active',
    campus_id = 'ctr_1794324944_0ae60d7c',
    seat_no = 'A02'
WHERE roll_no = 'QA1110002';

COMMIT;
