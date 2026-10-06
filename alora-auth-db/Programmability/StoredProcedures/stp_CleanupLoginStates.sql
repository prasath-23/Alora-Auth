/****** Object: Stored Procedure [stp_CleanupLoginStates] ******/
-- Housekeeping: removes abandoned sign-in states.
--
-- Implemented as a FUNCTION, not a PROCEDURE: the caller needs the result,
-- and PostgreSQL procedures cannot return a result set.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_CleanupLoginStates()
RETURNS INTEGER
LANGUAGE sql
VOLATILE
AS $$
    WITH del AS (
        DELETE FROM tbl_login_states
        WHERE  expires_at < now()
        RETURNING 1
    )
    SELECT count(*)::int FROM del;
$$;
