/****** Object: Table-valued Function [udf_GetAuthorizationCodeByHash] ******/
-- A code by its hash, spent or not: after a failed claim, it tells a replay
-- (whose product login must then be revoked) from an unknown code.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_GetAuthorizationCodeByHash(p_codeHash TEXT)
RETURNS SETOF tbl_authorization_codes
LANGUAGE sql
STABLE
AS $$
    SELECT * FROM tbl_authorization_codes a WHERE a.code_hash = p_codeHash;
$$;
