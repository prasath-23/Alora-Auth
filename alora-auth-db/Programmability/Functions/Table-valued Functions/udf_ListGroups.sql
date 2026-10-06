/****** Object: Table-valued Function [udf_ListGroups] ******/
-- The tenant's groups with their scopes, product grants and live member
-- counts.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_ListGroups(p_clientId TEXT)
RETURNS SETOF vw_GroupListItem
LANGUAGE sql
STABLE
AS $$
    SELECT * FROM vw_GroupListItem v WHERE v.client_id = p_clientId ORDER BY v.name;
$$;
