/****** Object: Table-valued Function [udf_GetProductClient] ******/
-- A product's client registration, without its secret.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_GetProductClient(p_productId TEXT)
RETURNS SETOF vw_ProductClient
LANGUAGE sql
STABLE
AS $$
    SELECT * FROM vw_ProductClient v WHERE v.id = p_productId;
$$;
