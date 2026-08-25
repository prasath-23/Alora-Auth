/****** Object: Table-valued Function [udf_GetGroupTenantScoped] ******/
-- Ownership check before any group mutation.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_GetGroupTenantScoped(p_groupId TEXT, p_clientId TEXT)
RETURNS SETOF tbl_groups
LANGUAGE sql
STABLE
AS $$
    SELECT * FROM tbl_groups g WHERE g.id = p_groupId AND g.client_id = p_clientId;
$$;
