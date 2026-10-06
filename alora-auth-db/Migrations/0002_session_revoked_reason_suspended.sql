/****** Migration: 0002_session_revoked_reason_suspended ******/
-- Adds the SUSPENDED value to "SessionRevokedReason", so suspending a company can
-- record WHY it ended each of the company's sessions (central and product alike).
--
-- WHY A MIGRATION
-- The enum types live in Programmability/Types/enums.sql as plain CREATE TYPE
-- statements, which build.sql applies ONLY when the type is absent (a DO-block
-- guard would hide them from sqlc). So an already-built database never picks up a
-- new value from a rebuild -- it needs this ALTER. A fresh build already creates
-- the type with SUSPENDED, where this migration's IF NOT EXISTS makes it a no-op.
--
-- ALTER TYPE ... ADD VALUE runs inside a transaction on PostgreSQL 12+ as long as
-- the new value is not USED in the same transaction; this migration only adds it.

BEGIN;

ALTER TYPE "SessionRevokedReason" ADD VALUE IF NOT EXISTS 'SUSPENDED';

COMMIT;

-- Verify the value is present, so a database that silently failed to gain it is
-- reported rather than left to fail later when a suspension tries to use it.
DO $$ BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_enum e
        JOIN   pg_type t ON t.oid = e.enumtypid
        WHERE  t.typname = 'SessionRevokedReason' AND e.enumlabel = 'SUSPENDED'
    ) THEN
        RAISE EXCEPTION 'SessionRevokedReason is missing SUSPENDED after migration';
    END IF;
END $$;
