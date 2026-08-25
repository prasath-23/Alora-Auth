/****** Object: Table-valued Function [udf_ListClientProducts] ******/
-- A tenant's subscriptions, shaped for the admin products page.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_ListClientProducts(p_clientId TEXT)
RETURNS SETOF vw_ClientProductDetail
LANGUAGE sql
STABLE
AS $$
    SELECT * FROM vw_ClientProductDetail v WHERE v.client_id = p_clientId ORDER BY v.product_name;
$$;
