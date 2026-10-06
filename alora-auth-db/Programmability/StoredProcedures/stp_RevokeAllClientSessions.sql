/****** Object: Stored Procedure [stp_RevokeAllClientSessions] ******/
-- Revokes every live login and generation across a whole company -- used
-- when a company is suspended, deactivated or cancelled, so its sessions END
-- rather than merely being gated and revived on reactivation. Mirrors
-- stp_RevokeAllUserSessions but scoped by client_id, which every family and
-- session row carries.
--
-- Implemented as a FUNCTION, not a PROCEDURE: the caller needs the result,
-- and PostgreSQL procedures cannot return a result set.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_RevokeAllClientSessions(p_clientId TEXT, p_reason "SessionRevokedReason")
RETURNS INTEGER
LANGUAGE sql
VOLATILE
AS $$
    WITH fam AS (
        UPDATE tbl_session_families
        SET    revoked_at     = now(),
               revoked_reason = p_reason
        WHERE  client_id   = p_clientId
          AND  revoked_at IS NULL
        RETURNING 1
    ), ses AS (
        UPDATE tbl_user_sessions
        SET    revoked_at     = now(),
               revoked_reason = p_reason
        WHERE  client_id   = p_clientId
          AND  revoked_at IS NULL
        RETURNING 1
    )
    SELECT count(*)::int FROM ses;
$$;
