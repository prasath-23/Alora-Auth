/****** Object: Stored Procedure [stp_RevokeSessionFamily] ******/
-- Revokes one login and every product login under it, tenant-scoped, with
-- all their live generations. Returns the number of logins revoked, so a
-- foreign or already-revoked id yields 0 and the caller answers 404.
--
-- Implemented as a FUNCTION, not a PROCEDURE: the caller needs the result,
-- and PostgreSQL procedures cannot return a result set.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_RevokeSessionFamily(p_familyId TEXT, p_clientId TEXT, p_reason "SessionRevokedReason")
RETURNS INTEGER
LANGUAGE sql
VOLATILE
AS $$
    WITH fam AS (
        UPDATE tbl_session_families
        SET    revoked_at     = now(),
               revoked_reason = p_reason
        WHERE  (id = p_familyId OR parent_family_id = p_familyId)
          AND  client_id   = p_clientId
          AND  revoked_at IS NULL
        RETURNING id
    ), ses AS (
        UPDATE tbl_user_sessions
        SET    revoked_at     = now(),
               revoked_reason = p_reason
        WHERE  family_id  IN (SELECT id FROM fam)
          AND  revoked_at IS NULL
        RETURNING 1
    )
    SELECT count(*)::int FROM fam;
$$;
