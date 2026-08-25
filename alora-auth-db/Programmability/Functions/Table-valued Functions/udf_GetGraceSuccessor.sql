/****** Object: Table-valued Function [udf_GetGraceSuccessor] ******/
-- Finds a still-live successor whose predecessor was the presented token,
-- created inside the grace window. Existence means the legitimate client
-- simply refreshed twice at once, so the caller answers 409 and leaves the
-- family intact rather than burning it.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_GetGraceSuccessor(p_prevTokenHash TEXT, p_createdAfter TIMESTAMPTZ)
RETURNS SETOF tbl_user_sessions
LANGUAGE sql
STABLE
AS $$
    SELECT * FROM tbl_user_sessions s
    WHERE  s.prev_token_hash = p_prevTokenHash
      AND  s.revoked_at     IS NULL
      AND  s.created_at      > p_createdAfter
    ORDER  BY s.created_at DESC
    LIMIT  1;
$$;
