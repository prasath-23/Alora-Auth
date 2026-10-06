/****** Object: Table-valued Function [udf_GetApiClient] ******/
-- One API client of a tenant; another tenant's id yields no rows.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_GetApiClient(p_apiClientId TEXT, p_clientId TEXT)
RETURNS SETOF vw_ApiClientSummary
LANGUAGE sql
STABLE
AS $$
    SELECT * FROM vw_ApiClientSummary v WHERE v.id = p_apiClientId AND v.client_id = p_clientId;
$$;
