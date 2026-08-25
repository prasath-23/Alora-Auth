/****** Object: Stored Procedure [stp_CleanupExpiredAuthCodes] ******/
-- Housekeeping sweep for expired codes. Safe to delete outright: an expired
-- code is unredeemable, so nothing references it.
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
        WHERE  expires_at < now()
        RETURNING 1
    )
    SELECT count(*)::int FROM del;
$$;
