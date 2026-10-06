/****** Object: Scalar-valued Function [udf_GetSystemGroupId] ******/
-- The id of one of a tenant's system groups (ADMINS), created with the
-- tenant.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_GetSystemGroupId(p_clientId TEXT, p_systemKey TEXT)
RETURNS TEXT
LANGUAGE sql
STABLE
AS $$
    SELECT g.id
    FROM   tbl_groups g
    WHERE  g.client_id  = p_clientId
      AND  g.system_key = p_systemKey;
$$;
