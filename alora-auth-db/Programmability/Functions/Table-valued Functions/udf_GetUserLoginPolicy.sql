/****** Object: Table-valued Function [udf_GetUserLoginPolicy] ******/
-- The login policy that applies to one user, already resolved.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_GetUserLoginPolicy(p_userId TEXT, p_clientId TEXT)
RETURNS SETOF vw_UserLoginPolicy
LANGUAGE sql
STABLE
AS $$
    SELECT * FROM vw_UserLoginPolicy v
    WHERE  v.user_id   = p_userId
      AND  v.client_id = p_clientId;
$$;
