/****** Object: Table-valued Function [udf_ListApiClientSecrets] ******/
-- An API client's secrets, newest first, without their hashes.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_ListApiClientSecrets(p_apiClientId TEXT, p_clientId TEXT)
RETURNS SETOF vw_ApiClientSecret
LANGUAGE sql
STABLE
AS $$
    SELECT * FROM vw_ApiClientSecret v
    WHERE  v.api_client_id = p_apiClientId
      AND  v.client_id     = p_clientId
    ORDER  BY v.created_at DESC;
$$;
