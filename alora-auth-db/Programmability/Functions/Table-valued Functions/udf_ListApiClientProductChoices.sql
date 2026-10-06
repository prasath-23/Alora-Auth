/****** Object: Table-valued Function [udf_ListApiClientProductChoices] ******/
-- The products a tenant may put on an API client's list: live subscriptions
-- to active products that accept API clients.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_ListApiClientProductChoices(p_clientId TEXT)
RETURNS SETOF vw_ClientProductDetail
LANGUAGE sql
STABLE
AS $$
    SELECT * FROM vw_ClientProductDetail v
    WHERE  v.client_id = p_clientId
      AND  v.is_active
      AND  v.starts_at <= now()
      AND  (v.ends_at IS NULL OR v.ends_at > now())
      AND  v.product_is_active
      AND  v.product_accepts_api_clients
    ORDER  BY v.product_name;
$$;
