/****** Object: Table-valued Function [udf_ListScopeReach] ******/
-- The user's reach, tenant-scoped: the scopes they hold plus those of the
-- groups they manage, one row per source. What rule 2 compares -- never what
-- grants.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_ListScopeReach(p_clientId TEXT, p_userId TEXT)
RETURNS SETOF vw_ScopeReach
LANGUAGE sql
STABLE
AS $$
    SELECT * FROM vw_ScopeReach v
    WHERE  v.client_id = p_clientId
      AND  v.user_id   = p_userId
    ORDER  BY v.scope, v.via;
$$;
