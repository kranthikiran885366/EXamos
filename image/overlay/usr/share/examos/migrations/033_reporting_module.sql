-- 033_reporting_module.sql — SPPIO / ExamOS reporting platform
--
-- Adds the server-side reporting primitives used by /api/v1/reports/*:
--   * safe epoch/date/number coercion for JSONB console records,
--   * an append-only report export history table with a content hash,
--   * supporting indexes for report source tables.
--
-- Reporting itself performs only SELECTs against existing authoritative
-- records. No report value is seeded, hardcoded or fabricated here.

BEGIN;

-- Convert either epoch seconds, epoch milliseconds or an ISO-8601 timestamp
-- held in JSONB text into epoch milliseconds. Invalid values return NULL so a
-- malformed legacy record cannot abort an aggregate query.
CREATE OR REPLACE FUNCTION report_epoch_ms(p_value TEXT)
RETURNS BIGINT
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    v TEXT;
    n NUMERIC;
BEGIN
    IF p_value IS NULL OR btrim(p_value) = '' THEN
        RETURN NULL;
    END IF;
    v := btrim(p_value);
    IF v ~ '^[0-9]{1,17}([.][0-9]+)?$' THEN
        n := v::numeric;
        -- Values above 1e11 are milliseconds; smaller values are seconds.
        IF n > 100000000000 THEN
            RETURN round(n)::bigint;
        END IF;
        RETURN round(n * 1000)::bigint;
    END IF;
    BEGIN
        RETURN (EXTRACT(EPOCH FROM v::timestamptz) * 1000)::bigint;
    EXCEPTION WHEN others THEN
        BEGIN
            RETURN (EXTRACT(EPOCH FROM v::timestamp) * 1000)::bigint;
        EXCEPTION WHEN others THEN
            RETURN NULL;
        END;
    END;
END;
$$;

-- Numeric coercion for JSONB text values. Invalid values return NULL.
CREATE OR REPLACE FUNCTION report_num(p_value TEXT)
RETURNS NUMERIC
LANGUAGE plpgsql
IMMUTABLE
AS $$
BEGIN
    IF p_value IS NULL OR btrim(p_value) = '' THEN
        RETURN NULL;
    END IF;
    RETURN btrim(p_value)::numeric;
EXCEPTION WHEN others THEN
    RETURN NULL;
END;
$$;

-- Boolean coercion for JSONB text values.
CREATE OR REPLACE FUNCTION report_bool(p_value TEXT)
RETURNS BOOLEAN
LANGUAGE plpgsql
IMMUTABLE
AS $$
BEGIN
    IF p_value IS NULL OR btrim(p_value) = '' THEN
        RETURN FALSE;
    END IF;
    RETURN lower(btrim(p_value)) IN ('true', 't', '1', 'yes', 'y');
END;
$$;

-- Safe JSONB array length (0 for missing/scalar values).
CREATE OR REPLACE FUNCTION report_json_array_len(p_value JSONB)
RETURNS INTEGER
LANGUAGE sql
IMMUTABLE
AS $$
    SELECT CASE WHEN p_value IS NOT NULL AND jsonb_typeof(p_value) = 'array'
                THEN jsonb_array_length(p_value) ELSE 0 END;
$$;

-- RFC 4180 cell rendering with spreadsheet formula-injection protection.
-- Any value starting with = + - @ TAB or CR is prefixed with a single quote
-- so a spreadsheet application cannot evaluate it as a formula.
CREATE OR REPLACE FUNCTION report_csv_escape(p_value TEXT)
RETURNS TEXT
LANGUAGE sql
IMMUTABLE
AS $$
    SELECT CASE
        WHEN p_value IS NULL OR p_value = '' THEN ''
        WHEN p_value ~ '^[=+\-@\t\r]'
            THEN '"''' || replace(p_value, '"', '""') || '"'
        WHEN p_value ~ '[",\n\r]'
            THEN '"' || replace(p_value, '"', '""') || '"'
        ELSE p_value
    END;
$$;

-- Render an ordered JSONB row set as CSV. p_columns is a JSONB array of
-- objects such as {"key":"rollNo","label":"Roll number"}.
CREATE OR REPLACE FUNCTION report_rows_csv(p_rows JSONB, p_columns JSONB)
RETURNS TEXT
LANGUAGE sql
IMMUTABLE
AS $$
    WITH cols AS (
        SELECT ord, c->>'key' AS key,
               COALESCE(c->>'label', c->>'key', '') AS label
        FROM jsonb_array_elements(COALESCE(p_columns, '[]'::jsonb))
             WITH ORDINALITY AS t(c, ord)
    ),
    header AS (
        SELECT string_agg(report_csv_escape(label), ',' ORDER BY ord) AS line
        FROM cols
    ),
    body AS (
        SELECT string_agg(
                   (SELECT string_agg(report_csv_escape(COALESCE(r->>key, '')), ',' ORDER BY ord)
                      FROM cols),
                   E'\n' ORDER BY ord_row) AS lines
        FROM jsonb_array_elements(COALESCE(p_rows, '[]'::jsonb))
             WITH ORDINALITY AS x(r, ord_row)
    )
    SELECT COALESCE((SELECT line FROM header), '')
           || COALESCE(E'\n' || (SELECT lines FROM body), '');
$$;

-- Append-only export history. An export row records exactly which report,
-- tenant scope, filters, format, row count and row hash was produced.
CREATE TABLE IF NOT EXISTS report_exports (
    id              VARCHAR(64) PRIMARY KEY,
    institution_id  VARCHAR(64),
    report_key      VARCHAR(64) NOT NULL,
    report_group    VARCHAR(24) NOT NULL
                      CHECK (report_group IN ('exams','devices','security','business')),
    export_format   VARCHAR(8) NOT NULL
                      CHECK (export_format IN ('csv','json')),
    filters         JSONB NOT NULL DEFAULT '{}'::jsonb,
    row_count       INTEGER NOT NULL CHECK (row_count >= 0),
    content_sha256  CHAR(64) NOT NULL
                      CHECK (content_sha256 ~ '^[0-9a-f]{64}$'),
    generated_by    VARCHAR(64) NOT NULL,
    generated_at    BIGINT NOT NULL,
    status          VARCHAR(16) NOT NULL DEFAULT 'completed'
                      CHECK (status IN ('completed','failed')),
    detail          TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_report_exports_tenant
    ON report_exports (institution_id, generated_at DESC);
CREATE INDEX IF NOT EXISTS idx_report_exports_report
    ON report_exports (report_key, generated_at DESC);
CREATE INDEX IF NOT EXISTS idx_report_exports_generated
    ON report_exports (generated_at DESC);

CREATE OR REPLACE FUNCTION reject_report_export_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'report export history is append-only';
END;
$$;

DROP TRIGGER IF EXISTS report_exports_append_only ON report_exports;
CREATE TRIGGER report_exports_append_only
    BEFORE UPDATE OR DELETE ON report_exports
    FOR EACH ROW EXECUTE FUNCTION reject_report_export_mutation();

-- Report source indexes used by the aggregation queries.
CREATE INDEX IF NOT EXISTS idx_examinations_inst_created
    ON examinations (institution_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_exam_attempts_exam_submitted
    ON exam_attempts (exam_id, submit_time DESC)
    WHERE status IN ('submitted','completed');
CREATE INDEX IF NOT EXISTS idx_device_evidence_verified
    ON device_attestation_evidence (device_id, verified_at DESC);
CREATE INDEX IF NOT EXISTS idx_security_events_tenant_at
    ON security_events (tenant_id, at DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_tenant_created
    ON incidents (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_support_requests_tenant_created
    ON support_requests (institution_id, created_at DESC);

INSERT INTO examos_schema_migrations (component, version)
VALUES ('reporting_module', 1)
ON CONFLICT (component, version) DO NOTHING;

COMMIT;
