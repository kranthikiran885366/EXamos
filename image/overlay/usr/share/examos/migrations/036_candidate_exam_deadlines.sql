BEGIN;

ALTER TABLE exam_sessions
    ADD COLUMN IF NOT EXISTS deadline_at BIGINT;

UPDATE exam_sessions s
SET deadline_at = LEAST(
    s.launched_at + e.duration_minutes::BIGINT * 60000,
    COALESCE(
        (
            SELECT CASE
                WHEN schedule.end_time < 10000000000 THEN schedule.end_time * 1000
                ELSE schedule.end_time
            END
            FROM exam_schedules schedule
            WHERE schedule.exam_id = s.examination_id
            ORDER BY schedule.start_time ASC
            LIMIT 1
        ),
        s.launched_at + e.duration_minutes::BIGINT * 60000
    )
)
FROM examinations e
WHERE e.id = s.examination_id
  AND s.launched_at IS NOT NULL
  AND s.deadline_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_exam_sessions_candidate_deadline
    ON exam_sessions(deadline_at)
    WHERE deadline_at IS NOT NULL AND status IN ('authorized', 'active', 'interrupted', 'resuming');

INSERT INTO examos_schema_migrations(component, version)
VALUES ('candidate_exam_runtime', 2)
ON CONFLICT (component, version) DO NOTHING;

COMMIT;
