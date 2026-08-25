/****** Object: Table-valued Function [udf_GetClientSessionById] ******/
-- Tenant-scoped session lookup for the admin revoke path.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_GetClientSessionById(p_sessionId TEXT, p_clientId TEXT)
RETURNS SETOF vw_SessionOwner
LANGUAGE sql
STABLE
AS $$
    SELECT * FROM vw_SessionOwner v WHERE v.id = p_sessionId AND v.client_id = p_clientId;
$$;
