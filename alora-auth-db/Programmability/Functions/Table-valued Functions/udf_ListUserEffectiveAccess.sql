/****** Object: Table-valued Function [udf_ListUserEffectiveAccess] ******/
-- Every effective role of one user, with where it comes from.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_ListUserEffectiveAccess(p_userId TEXT, p_clientId TEXT)
RETURNS SETOF vw_EffectiveProductRole
LANGUAGE sql
STABLE
AS $$
    SELECT * FROM vw_EffectiveProductRole v
    WHERE  v.user_id   = p_userId
      AND  v.client_id = p_clientId
    ORDER  BY v.product_name, v.role_name;
$$;
