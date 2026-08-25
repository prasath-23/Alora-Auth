/****** Object: Stored Procedure [stp_RevokeSession] ******/
-- Revokes one session, tenant-scoped and idempotent (already-revoked rows
-- are skipped). Returns the affected count so a cross-tenant id yields 404.
--
-- Implemented as a FUNCTION, not a PROCEDURE: the caller needs the result,
-- and PostgreSQL procedures cannot return a result set.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_RevokeSession(p_sessionId TEXT, p_clientId TEXT, p_reason "SessionRevokedReason")
RETURNS INTEGER
LANGUAGE sql
VOLATILE
AS $$
    WITH upd AS (
        UPDATE tbl_user_sessions
        SET    revoked_at     = now(),
               revoked_reason = p_reason
        WHERE  id          = p_sessionId
          AND  client_id   = p_clientId
          AND  revoked_at IS NULL
        RETURNING 1
    )
    SELECT count(*)::int FROM upd;
$$;
