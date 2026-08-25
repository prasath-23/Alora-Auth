/****** Object: Table-valued Function [udf_GetUserCredentialByEmail] ******/
-- The login lookup. Cross-tenant on purpose: an address identifies at most
-- one live password account, so the tenant is derived FROM the user rather
-- than supplied by the caller.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_GetUserCredentialByEmail(p_email TEXT)
RETURNS SETOF vw_UserCredential
LANGUAGE sql
STABLE
AS $$
    SELECT * FROM vw_UserCredential v WHERE lower(v.email) = lower(p_email) LIMIT 1;
$$;
