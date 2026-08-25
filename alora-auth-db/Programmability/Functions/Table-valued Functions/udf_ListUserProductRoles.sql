/****** Object: Table-valued Function [udf_ListUserProductRoles] ******/
-- The user's active product roles. These become the JWT roles claim, so the
-- tenant predicate here is what keeps another organisation's grant out of a
-- token.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_ListUserProductRoles(p_userId TEXT, p_clientId TEXT)
RETURNS SETOF vw_UserProductRole
LANGUAGE sql
STABLE
AS $$
    SELECT * FROM vw_UserProductRole v
    WHERE  v.user_id   = p_userId
      AND  v.client_id = p_clientId;
$$;
