/****** Object: Table-valued Function [udf_ListSessionFamilies] ******/
-- The admin session list, capped so one tenant cannot request an unbounded
-- result set. The view already excludes token material.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_ListSessionFamilies(p_clientId TEXT)
RETURNS SETOF vw_SessionFamilySummary
LANGUAGE sql
STABLE
AS $$
    SELECT * FROM vw_SessionFamilySummary v
    WHERE  v.client_id = p_clientId
    ORDER  BY v.last_seen_at DESC
    LIMIT  200;
$$;
