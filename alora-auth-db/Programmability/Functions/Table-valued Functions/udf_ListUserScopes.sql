/****** Object: Table-valued Function [udf_ListUserScopes] ******/
-- Every App Central scope the user holds, one row per source (each group,
-- and their extras), tenant-scoped. What the rules compare, and what the UI
-- shows under 'where it comes from'.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_ListUserScopes(p_clientId TEXT, p_userId TEXT)
RETURNS SETOF vw_EffectiveScope
LANGUAGE sql
STABLE
AS $$
    SELECT * FROM vw_EffectiveScope v
    WHERE  v.client_id = p_clientId
      AND  v.user_id   = p_userId
    ORDER  BY v.scope, v.source, v.group_name;
$$;
