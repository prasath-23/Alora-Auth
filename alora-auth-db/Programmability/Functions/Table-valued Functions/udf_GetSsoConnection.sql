/****** Object: Table-valued Function [udf_GetSsoConnection] ******/
-- What the SSO login path needs about one connection, secret ciphertext
-- included. Never returned by any API.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_GetSsoConnection(p_connectionId TEXT)
RETURNS SETOF vw_SsoConnectionRuntime
LANGUAGE sql
STABLE
AS $$
    SELECT * FROM vw_SsoConnectionRuntime v WHERE v.id = p_connectionId;
$$;
