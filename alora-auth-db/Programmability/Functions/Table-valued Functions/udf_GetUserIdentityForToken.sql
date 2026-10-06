/****** Object: Table-valued Function [udf_GetUserIdentityForToken] ******/
-- The token-minting identity. Returns zero rows for a deprovisioned account
-- or a suspended tenant, which the caller maps to a refusal.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_GetUserIdentityForToken(p_userId TEXT)
RETURNS SETOF vw_UserIdentity
LANGUAGE sql
STABLE
AS $$
    SELECT * FROM vw_UserIdentity v WHERE v.id = p_userId;
$$;
