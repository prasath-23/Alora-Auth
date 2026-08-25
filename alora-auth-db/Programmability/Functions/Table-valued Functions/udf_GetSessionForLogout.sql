/****** Object: Table-valued Function [udf_GetSessionForLogout] ******/
-- Minimal identity for logout. No lock is taken: logout is idempotent, so a
-- concurrent revoke is harmless.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_GetSessionForLogout(p_tokenHash TEXT)
RETURNS SETOF vw_SessionOwner
LANGUAGE sql
STABLE
AS $$
    SELECT * FROM vw_SessionOwner v WHERE v.refresh_token_hash = p_tokenHash;
$$;
