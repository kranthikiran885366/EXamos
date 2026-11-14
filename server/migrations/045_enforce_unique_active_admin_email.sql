-- 045_enforce_unique_active_admin_email.sql
-- Enforce strict email uniqueness across active administrator and user records.
-- Prevents duplicate administrator accounts when invites or registrations are retried.

BEGIN;

-- 1. Deduplicate any existing active records sharing the same normalized email address.
-- Preserve the account with MFA enrolled, or the most recently created/updated active account.
WITH duplicates AS (
    SELECT id,
           ROW_NUMBER() OVER (
               PARTITION BY LOWER(TRIM(email))
               ORDER BY COALESCE(mfa_enabled, 0) DESC, created_at DESC, id DESC
           ) AS rn
    FROM users
    WHERE LOWER(COALESCE(status, '')) = 'active'
      AND email IS NOT NULL
      AND TRIM(email) <> ''
)
UPDATE users
SET status = 'superseded',
    status_reason = 'Deactivated by migration 045: duplicate active email deduplication',
    status_at = EXTRACT(EPOCH FROM NOW())::BIGINT
WHERE id IN (SELECT id FROM duplicates WHERE rn > 1);

-- 2. Define the trigger function to prevent concurrent duplicate active email insertions
CREATE OR REPLACE FUNCTION examos_enforce_unique_active_user_email()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE normalized_email TEXT;
BEGIN
  normalized_email := lower(btrim(COALESCE(NEW.email, '')));
  IF normalized_email = '' OR lower(COALESCE(NEW.status, '')) <> 'active' THEN
    RETURN NEW;
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended(normalized_email, 72819431));
  IF EXISTS (
    SELECT 1 FROM users u
    WHERE u.id IS DISTINCT FROM NEW.id
      AND lower(btrim(COALESCE(u.email, ''))) = normalized_email
      AND lower(COALESCE(u.status, '')) = 'active'
  ) THEN
    RAISE EXCEPTION 'An active account already uses this email address'
      USING ERRCODE = '23505', CONSTRAINT = 'users_active_email_normalized_key';
  END IF;
  RETURN NEW;
END;
$$;

-- 3. Install the before-insert/update trigger on users
DROP TRIGGER IF EXISTS users_active_email_unique_guard ON users;
CREATE TRIGGER users_active_email_unique_guard
BEFORE INSERT OR UPDATE OF email, status ON users
FOR EACH ROW EXECUTE FUNCTION examos_enforce_unique_active_user_email();

-- 4. Create partial unique index as a secondary immutable schema constraint
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_active_email_normalized
ON users (LOWER(TRIM(email)))
WHERE LOWER(COALESCE(status, '')) = 'active' AND email IS NOT NULL AND TRIM(email) <> '';

-- 5. Record version marker in schema migrations table
INSERT INTO examos_schema_migrations(component, version)
VALUES ('admin_auth', 11)
ON CONFLICT (component, version) DO NOTHING;

COMMIT;
