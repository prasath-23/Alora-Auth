/****** Object: Stored Procedure [stp_SetUserActive] ******/
-- Enables or disables a member, tenant-scoped. Returns the affected-row
-- count so the caller can answer 404 for an unknown or another tenant's user
-- rather than silently reporting success.
--
-- Implemented as a FUNCTION, not a PROCEDURE: the caller needs the result,
-- and PostgreSQL procedures cannot return a result set.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_SetUserActive(p_userId TEXT, p_clientId TEXT, p_isActive BOOLEAN)
RETURNS INTEGER
LANGUAGE sql
VOLATILE
AS $$
    WITH upd AS (
        UPDATE tbl_users
        SET    is_active  = p_isActive,
               updated_at = now()
        WHERE  id        = p_userId
          AND  client_id = p_clientId
        RETURNING 1
    )
    SELECT count(*)::int FROM upd;
$$;
