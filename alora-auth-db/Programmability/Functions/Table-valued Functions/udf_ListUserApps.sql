/****** Object: Table-valued Function [udf_ListUserApps] ******/
-- The products a user may open from App Central.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_ListUserApps(p_userId TEXT, p_clientId TEXT)
RETURNS SETOF vw_UserApp
LANGUAGE sql
STABLE
AS $$
    SELECT * FROM vw_UserApp v
    WHERE  v.user_id   = p_userId
      AND  v.client_id = p_clientId
    ORDER  BY v.product_name;
$$;
