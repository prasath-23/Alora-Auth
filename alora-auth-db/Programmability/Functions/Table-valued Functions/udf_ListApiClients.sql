/****** Object: Table-valued Function [udf_ListApiClients] ******/
-- A tenant's API clients, by name.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_ListApiClients(p_clientId TEXT)
RETURNS SETOF vw_ApiClientSummary
LANGUAGE sql
STABLE
AS $$
    SELECT * FROM vw_ApiClientSummary v WHERE v.client_id = p_clientId ORDER BY lower(v.name);
$$;
