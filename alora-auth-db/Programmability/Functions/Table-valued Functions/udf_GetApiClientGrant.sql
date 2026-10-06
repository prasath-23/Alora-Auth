/****** Object: Table-valued Function [udf_GetApiClientGrant] ******/
-- Whether an API client may have a token for a product on its list right
-- now, and with which scopes. No row: the product is unknown, or not on the
-- list.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_GetApiClientGrant(p_apiClientId TEXT, p_productKey TEXT)
RETURNS SETOF vw_ApiClientGrant
LANGUAGE sql
STABLE
AS $$
    SELECT * FROM vw_ApiClientGrant v
    WHERE  v.api_client_id = p_apiClientId
      AND  v.product_key   = p_productKey;
$$;
