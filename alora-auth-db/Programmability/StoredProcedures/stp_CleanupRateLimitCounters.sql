/****** Object: Stored Procedure [stp_CleanupRateLimitCounters] ******/
-- Housekeeping: removes expired rate-limit counters.
--
-- Implemented as a FUNCTION, not a PROCEDURE: the caller needs the result,
-- and PostgreSQL procedures cannot return a result set.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_CleanupRateLimitCounters()
RETURNS INTEGER
LANGUAGE sql
VOLATILE
AS $$
    WITH del AS (
        DELETE FROM tbl_rate_limit_counters
        WHERE  reset_at < now()
        RETURNING 1
    )
    SELECT count(*)::int FROM del;
$$;
