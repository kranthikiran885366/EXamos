BEGIN;

CREATE TABLE IF NOT EXISTS console_records (
  collection VARCHAR(48) NOT NULL,
  record_id VARCHAR(128) NOT NULL,
  institution_id VARCHAR(64),
  data JSONB NOT NULL,
  created_by VARCHAR(64) NOT NULL,
  updated_by VARCHAR(64) NOT NULL,
  created_at BIGINT NOT NULL,
  updated_at BIGINT NOT NULL,
  PRIMARY KEY (collection, record_id)
);

CREATE INDEX IF NOT EXISTS idx_console_records_tenant
  ON console_records (collection, institution_id, updated_at DESC);

INSERT INTO examos_schema_migrations (component, version)
VALUES ('console_record_store', 1)
ON CONFLICT (component, version) DO NOTHING;

COMMIT;
