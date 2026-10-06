/****** Object: Stored Procedure [stp_RateLimitHit] ******/
-- Spends one unit against a fixed-window counter and returns NULL when the
-- hit is allowed, or the window's reset time when it is over p_max (so the
-- caller can set Retry-After). One atomic upsert: the ON CONFLICT row lock
-- serialises concurrent hits of the same key across every instance, so N
-- processes share one budget. An expired window resets to a single hit;
-- otherwise the count rises. Returning the reset time only on refusal keeps
-- this a single scalar sqlc can type.
--
-- Implemented as a FUNCTION, not a PROCEDURE: the caller needs the result,
-- and PostgreSQL procedures cannot return a result set.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_RateLimitHit(p_key TEXT, p_max INTEGER, p_windowSecs INTEGER)
RETURNS TIMESTAMPTZ
LANGUAGE sql
VOLATILE
AS $$
    INSERT INTO tbl_rate_limit_counters AS c (bucket_key, hits, reset_at)
    VALUES (p_key, 1, now() + make_interval(secs => p_windowSecs))
    ON CONFLICT (bucket_key) DO UPDATE
    SET hits     = CASE WHEN c.reset_at <= now() THEN 1 ELSE c.hits + 1 END,
        reset_at = CASE WHEN c.reset_at <= now()
                        THEN now() + make_interval(secs => p_windowSecs)
                        ELSE c.reset_at END
    RETURNING CASE WHEN c.hits <= p_max THEN NULL ELSE c.reset_at END;
$$;
