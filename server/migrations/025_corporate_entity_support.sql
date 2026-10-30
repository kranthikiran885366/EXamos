-- Migration 025: Corporate / Company / Recruitment Entity Support
-- Adds entity_type, corporate metadata, and recruitment-specific columns to
-- tenants and institution_applications tables. Adds recruitment_drives table
-- for companies running hiring assessments.

-- ============================================================
-- 1. Extend tenants with entity type and corporate metadata
-- ============================================================
ALTER TABLE tenants
  ADD COLUMN IF NOT EXISTS entity_type         VARCHAR(40)  NOT NULL DEFAULT 'university',
  ADD COLUMN IF NOT EXISTS company_size        VARCHAR(30),       -- startup|smb|mid_market|enterprise|large_enterprise
  ADD COLUMN IF NOT EXISTS industry_sector     VARCHAR(80),       -- e.g. technology, banking, pharma, government
  ADD COLUMN IF NOT EXISTS hiring_volume       INTEGER      DEFAULT 0, -- annual candidate count for recruitment
  ADD COLUMN IF NOT EXISTS hr_contact_name     VARCHAR(120),
  ADD COLUMN IF NOT EXISTS hr_contact_email    VARCHAR(120),
  ADD COLUMN IF NOT EXISTS tech_stack          TEXT,              -- free-text: comma-separated technologies
  ADD COLUMN IF NOT EXISTS linkedin_url        VARCHAR(255),
  ADD COLUMN IF NOT EXISTS website_url         VARCHAR(255);

-- ============================================================
-- 2. Extend institution_applications with corporate fields
-- ============================================================
ALTER TABLE institution_applications
  ADD COLUMN IF NOT EXISTS company_size        VARCHAR(30),
  ADD COLUMN IF NOT EXISTS industry_sector     VARCHAR(80),
  ADD COLUMN IF NOT EXISTS hiring_volume       INTEGER      DEFAULT 0,
  ADD COLUMN IF NOT EXISTS hr_contact_name     VARCHAR(120),
  ADD COLUMN IF NOT EXISTS hr_contact_email    VARCHAR(120),
  ADD COLUMN IF NOT EXISTS tech_stack          TEXT,
  ADD COLUMN IF NOT EXISTS linkedin_url        VARCHAR(255),
  ADD COLUMN IF NOT EXISTS website_url         VARCHAR(255),
  ADD COLUMN IF NOT EXISTS annual_exam_count   INTEGER      DEFAULT 0,
  ADD COLUMN IF NOT EXISTS job_roles_targeted  TEXT;          -- comma-separated: e.g. "SDE,QA,PM,Data Analyst"

-- ============================================================
-- 3. Recruitment drives — companies run assessment campaigns
-- ============================================================
CREATE TABLE IF NOT EXISTS recruitment_drives (
  id                   VARCHAR(64)   PRIMARY KEY,
  institution_id       VARCHAR(64)   NOT NULL,
  title                VARCHAR(160)  NOT NULL,
  description          TEXT,
  drive_type           VARCHAR(40)   NOT NULL DEFAULT 'campus_hiring',
                                    -- campus_hiring | lateral_hiring | internship | certification | appraisal
  industry_sector      VARCHAR(80),
  job_roles            TEXT,         -- comma-separated target job roles
  target_candidate_count INTEGER     DEFAULT 0,
  registered_count     INTEGER       DEFAULT 0,
  appeared_count       INTEGER       DEFAULT 0,
  shortlisted_count    INTEGER       DEFAULT 0,
  selected_count       INTEGER       DEFAULT 0,
  status               VARCHAR(30)   NOT NULL DEFAULT 'DRAFT',
                                    -- DRAFT | PUBLISHED | REGISTRATION_OPEN | ACTIVE | COMPLETED | CANCELLED
  application_deadline BIGINT,
  drive_start_date     BIGINT,
  drive_end_date       BIGINT,
  result_publish_date  BIGINT,
  assessment_config    JSONB         NOT NULL DEFAULT '{}'::jsonb,
  eligibility_criteria JSONB         NOT NULL DEFAULT '{}'::jsonb,
  exam_ids             JSONB         NOT NULL DEFAULT '[]'::jsonb,
  campus_ids           JSONB         NOT NULL DEFAULT '[]'::jsonb,
  hr_contact_name      VARCHAR(120),
  hr_contact_email     VARCHAR(120),
  created_by           VARCHAR(64),
  created_at           BIGINT        NOT NULL,
  updated_at           BIGINT        NOT NULL,
  CONSTRAINT fk_drive_tenant FOREIGN KEY (institution_id) REFERENCES tenants(id)
);

CREATE INDEX IF NOT EXISTS idx_recruitment_drives_institution ON recruitment_drives(institution_id);
CREATE INDEX IF NOT EXISTS idx_recruitment_drives_status      ON recruitment_drives(status);

-- ============================================================
-- 4. Candidate assessments — per-candidate test results in drives
-- ============================================================
CREATE TABLE IF NOT EXISTS drive_candidate_results (
  id                   VARCHAR(64)   PRIMARY KEY,
  drive_id             VARCHAR(64)   NOT NULL,
  candidate_id         VARCHAR(64)   NOT NULL,
  institution_id       VARCHAR(64)   NOT NULL,
  exam_id              VARCHAR(64),
  name                 VARCHAR(120),
  email                VARCHAR(120),
  phone                VARCHAR(40),
  resume_url           VARCHAR(255),
  status               VARCHAR(30)   NOT NULL DEFAULT 'REGISTERED',
                                    -- REGISTERED | APPEARED | SHORTLISTED | SELECTED | REJECTED | WAITLISTED
  score                NUMERIC(8,2)  DEFAULT 0,
  percentile           NUMERIC(6,2)  DEFAULT 0,
  rank_in_drive        INTEGER       DEFAULT 0,
  job_role_applied     VARCHAR(80),
  location_preference  VARCHAR(80),
  submitted_at         BIGINT,
  result_published_at  BIGINT,
  created_at           BIGINT        NOT NULL,
  CONSTRAINT fk_drive_result_drive      FOREIGN KEY (drive_id)      REFERENCES recruitment_drives(id),
  CONSTRAINT fk_drive_result_tenant     FOREIGN KEY (institution_id) REFERENCES tenants(id)
);

CREATE INDEX IF NOT EXISTS idx_drive_results_drive       ON drive_candidate_results(drive_id);
CREATE INDEX IF NOT EXISTS idx_drive_results_candidate   ON drive_candidate_results(candidate_id);
CREATE INDEX IF NOT EXISTS idx_drive_results_institution ON drive_candidate_results(institution_id);
CREATE INDEX IF NOT EXISTS idx_drive_results_status      ON drive_candidate_results(status);

-- ============================================================
-- 5. Extend departments with company-specific context
-- ============================================================
ALTER TABLE departments
  ADD COLUMN IF NOT EXISTS business_function   VARCHAR(80),  -- for corporate: e.g. Engineering, HR, Finance
  ADD COLUMN IF NOT EXISTS head_name           VARCHAR(120),
  ADD COLUMN IF NOT EXISTS head_email          VARCHAR(120),
  ADD COLUMN IF NOT EXISTS employee_count      INTEGER       DEFAULT 0;

-- ============================================================
-- 6. Indexes on new tenant columns for fast entity-type queries
-- ============================================================
CREATE INDEX IF NOT EXISTS idx_tenants_entity_type      ON tenants(entity_type);
CREATE INDEX IF NOT EXISTS idx_tenants_industry_sector  ON tenants(industry_sector);

-- ============================================================
-- 7. Back-fill entity_type for existing tenants (default to university)
-- ============================================================
UPDATE tenants SET entity_type = 'university' WHERE entity_type IS NULL OR entity_type = '';
