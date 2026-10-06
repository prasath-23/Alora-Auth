/****** Object: Table-valued Function [udf_ListSsoConnections] ******/
-- A tenant's SSO connections, without secrets.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_ListSsoConnections(p_clientId TEXT)
RETURNS SETOF vw_SsoConnectionSummary
LANGUAGE sql
STABLE
AS $$
    SELECT * FROM vw_SsoConnectionSummary v WHERE v.client_id = p_clientId ORDER BY v.name;
$$;
