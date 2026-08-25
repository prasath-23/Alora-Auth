/****** Object: Table-valued Function [udf_GetOAuthLinkableUser] ******/
-- The federated-login link target: an existing OAUTH_ONLY account in this
-- tenant. Restricted to OAUTH_ONLY so a Google sign-in can never take over
-- an account that has its own password.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_GetOAuthLinkableUser(p_clientId TEXT, p_email TEXT)
RETURNS SETOF vw_UserTenantScoped
LANGUAGE sql
STABLE
AS $$
    SELECT * FROM vw_UserTenantScoped v
    WHERE  v.client_id     = p_clientId
      AND  lower(v.email)  = lower(p_email)
      AND  v.is_active      = true
      AND  v.account_type   = 'OAUTH_ONLY'
    LIMIT  1;
$$;
