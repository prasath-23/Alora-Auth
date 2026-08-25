/****** Object: Table-valued Function [udf_GetUserTenantScoped] ******/
-- Ownership check for any admin operation on a member. Zero rows means
-- either no such user or another tenant's user, and the caller cannot tell
-- which.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_GetUserTenantScoped(p_userId TEXT, p_clientId TEXT)
RETURNS SETOF vw_UserTenantScoped
LANGUAGE sql
STABLE
AS $$
    SELECT * FROM vw_UserTenantScoped v WHERE v.id = p_userId AND v.client_id = p_clientId;
$$;
