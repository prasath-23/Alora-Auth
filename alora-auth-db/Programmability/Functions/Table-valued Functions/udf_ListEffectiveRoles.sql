/****** Object: Table-valued Function [udf_ListEffectiveRoles] ******/
-- The distinct roles a user effectively holds in ONE product. Empty means no
-- access; this is what a product token's roles claim is built from.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_ListEffectiveRoles(p_userId TEXT, p_clientId TEXT, p_productId TEXT)
RETURNS SETOF TEXT
LANGUAGE sql
STABLE
AS $$
    SELECT DISTINCT v.role_name
    FROM   vw_EffectiveProductRole v
    WHERE  v.user_id    = p_userId
      AND  v.client_id  = p_clientId
      AND  v.product_id = p_productId
    ORDER  BY v.role_name;
$$;
