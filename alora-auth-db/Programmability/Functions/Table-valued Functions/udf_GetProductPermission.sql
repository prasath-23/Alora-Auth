/****** Object: Table-valued Function [udf_GetProductPermission] ******/
-- A single grant, for existence checks.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_GetProductPermission(p_userId TEXT, p_clientId TEXT, p_productId TEXT)
RETURNS SETOF vw_UserProductRole
LANGUAGE sql
STABLE
AS $$
    SELECT * FROM vw_UserProductRole v
    WHERE  v.user_id    = p_userId
      AND  v.client_id  = p_clientId
      AND  v.product_id = p_productId;
$$;
