/****** Object: Stored Procedure [stp_RevokeAllUserSessions] ******/
-- Revokes every live login and generation of a user -- used on password
-- change, reset and deactivation. Scoped by user_id alone is safe because
-- the composite tenant foreign key pins a user to exactly one tenant.
--
-- Implemented as a FUNCTION, not a PROCEDURE: the caller needs the result,
-- and PostgreSQL procedures cannot return a result set.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_RevokeAllUserSessions(p_userId TEXT, p_reason "SessionRevokedReason")
RETURNS INTEGER
LANGUAGE sql
VOLATILE
AS $$
    WITH fam AS (
        UPDATE tbl_session_families
        SET    revoked_at     = now(),
               revoked_reason = p_reason
        WHERE  user_id     = p_userId
          AND  revoked_at IS NULL
        RETURNING 1
    ), ses AS (
        UPDATE tbl_user_sessions
        SET    revoked_at     = now(),
               revoked_reason = p_reason
        WHERE  user_id     = p_userId
          AND  revoked_at IS NULL
        RETURNING 1
    )
    SELECT count(*)::int FROM ses;
$$;
