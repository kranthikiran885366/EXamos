BEGIN;

ALTER TABLE student_import_row_results
    ADD COLUMN IF NOT EXISTS email VARCHAR(128) NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS course VARCHAR(128) NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS batch VARCHAR(64) NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS semester INTEGER NOT NULL DEFAULT 1,
    ADD COLUMN IF NOT EXISTS section VARCHAR(32) NOT NULL DEFAULT '';

ALTER TABLE students
    ALTER COLUMN verification_status SET DEFAULT 'UNVERIFIED';

UPDATE students s
SET verification_status = 'UNVERIFIED'
WHERE lower(COALESCE(s.verification_status, '')) = 'verified'
  AND NOT EXISTS (
      SELECT 1
      FROM student_verification_records v
      WHERE v.student_id = s.id
        AND upper(v.status) = 'VERIFIED'
  );

INSERT INTO examos_schema_migrations(component, version)
VALUES ('students', 2)
ON CONFLICT (component, version) DO NOTHING;

COMMIT;
