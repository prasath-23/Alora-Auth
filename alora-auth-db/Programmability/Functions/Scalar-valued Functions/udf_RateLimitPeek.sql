/****** Object: Scalar-valued Function [udf_RateLimitPeek] ******/
-- The reset time of a shared fixed-window counter that has ALREADY reached
-- p_max, or NULL when the key is still within budget or its window has
-- passed. Read-only -- it spends nothing: the failure-budget check consults
-- it before running a request and spends a unit only when the request then
-- fails.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_RateLimitPeek(p_key TEXT, p_max INTEGER)
RETURNS TIMESTAMPTZ
LANGUAGE sql
STABLE
AS $$
    SELECT c.reset_at
    FROM   tbl_rate_limit_counters c
    WHERE  c.bucket_key = p_key
      AND  c.reset_at   > now()
      AND  c.hits      >= p_max;
$$;
