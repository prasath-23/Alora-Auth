/****** Object: Table-valued Function [udf_GetUserFreshness] ******/
-- One row per request for the staleness check. Unfiltered by design so the
-- caller can distinguish inactive from deleted from missing.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_GetUserFreshness(p_userId TEXT)
RETURNS SETOF vw_UserFreshness
LANGUAGE sql
STABLE
AS $$
    SELECT * FROM vw_UserFreshness v WHERE v.id = p_userId;
$$;
