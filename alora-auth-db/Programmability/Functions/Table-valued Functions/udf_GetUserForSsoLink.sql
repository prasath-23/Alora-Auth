/****** Object: Table-valued Function [udf_GetUserForSsoLink] ******/
-- The account a first SSO sign-in may link to: a live, active member of the
-- connection's OWN tenant with this address. SSO never creates accounts.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_GetUserForSsoLink(p_clientId TEXT, p_email TEXT)
RETURNS SETOF vw_UserTenantScoped
LANGUAGE sql
STABLE
AS $$
    SELECT * FROM vw_UserTenantScoped v
    WHERE  v.client_id     = p_clientId
      AND  lower(v.email)  = lower(p_email)
      AND  v.is_active      = true
    LIMIT  1;
$$;
