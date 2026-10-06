/****** Object: Table-valued Function [udf_GetProductClientCredential] ******/
-- The secret hash of a product, for client authentication only.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_GetProductClientCredential(p_productId TEXT)
RETURNS SETOF vw_ProductClientCredential
LANGUAGE sql
STABLE
AS $$
    SELECT * FROM vw_ProductClientCredential v WHERE v.id = p_productId;
$$;
