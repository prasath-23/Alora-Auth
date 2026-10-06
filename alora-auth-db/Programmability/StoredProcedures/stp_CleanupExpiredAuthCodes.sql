/****** Object: Stored Procedure [stp_CleanupExpiredAuthCodes] ******/
-- Housekeeping sweep. A code is kept for an hour past its expiry, so a
-- replay arriving late is still recognised as one; after that it is deleted
-- outright.
--
-- Implemented as a FUNCTION, not a PROCEDURE: the caller needs the result,
-- and PostgreSQL procedures cannot return a result set.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_CleanupExpiredAuthCodes()
RETURNS INTEGER
LANGUAGE sql
VOLATILE
AS $$
    WITH del AS (
        DELETE FROM tbl_authorization_codes
        WHERE  expires_at < now() - interval '1 hour'
        RETURNING 1
    )
    SELECT count(*)::int FROM del;
$$;
