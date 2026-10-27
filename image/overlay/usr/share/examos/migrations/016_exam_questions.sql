BEGIN;

-- Migration 016: exam question bank.
--
-- exam_engine_load_questions_from_db() queries this table to populate the
-- in-process question array. Without it exam_engine_is_ready() always
-- returns 0 and paper delivery is permanently blocked (ISS-01).
--
-- Each row belongs to exactly one exam. question_order controls delivery
-- sequence. active=false rows are excluded from paper delivery so questions
-- can be retired without deletion.

CREATE TABLE IF NOT EXISTS examos_exam_questions (
    question_id     bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    exam_id         varchar(63) NOT NULL
                        REFERENCES examos_exams(exam_id) ON DELETE CASCADE,
    question_order  integer NOT NULL DEFAULT 1 CHECK (question_order >= 1),
    section         varchar(31) NOT NULL DEFAULT 'General',
    question_text   text NOT NULL,
    option_a        text NOT NULL DEFAULT '',
    option_b        text NOT NULL DEFAULT '',
    option_c        text NOT NULL DEFAULT '',
    option_d        text NOT NULL DEFAULT '',
    correct_option  smallint NOT NULL DEFAULT 0
                        CHECK (correct_option BETWEEN 0 AND 3),
    marks           integer NOT NULL DEFAULT 1 CHECK (marks >= 0),
    question_type   varchar(15) NOT NULL DEFAULT 'MCQ'
                        CHECK (question_type IN ('MCQ', 'NUMERICAL', 'CODING')),
    code_template   text NOT NULL DEFAULT '',
    active          boolean NOT NULL DEFAULT true,
    created_at      timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (exam_id, question_order)
);

CREATE INDEX IF NOT EXISTS examos_exam_questions_exam_active_idx
    ON examos_exam_questions (exam_id, question_order)
    WHERE active = true;

INSERT INTO examos_schema_migrations (component, version)
VALUES ('exam_lifecycle', 5)
ON CONFLICT (component, version) DO NOTHING;

COMMIT;
