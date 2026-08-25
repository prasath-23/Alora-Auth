/****** Object: Table-valued Function [udf_GetUserIdentityForToken] ******/
-- The token-minting identity. Returns zero rows for a deprovisioned account,
-- which the caller maps to 403 — this is what stops a token being issued to
-- a user disabled during the authorization-code window.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_GetUserIdentityForToken(p_userId TEXT)
RETURNS SETOF vw_UserIdentity
LANGUAGE sql
STABLE
AS $$
    SELECT * FROM vw_UserIdentity v WHERE v.id = p_userId;
$$;
