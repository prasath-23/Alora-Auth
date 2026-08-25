/****** Object: Scalar-valued Function [udf_ProductKeyById] ******/
-- The product's audience key, used to scope a minted token to one product.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_ProductKeyById(p_productId TEXT)
RETURNS TEXT
LANGUAGE sql
STABLE
AS $$
    SELECT p.key FROM tbl_products p WHERE p.id = p_productId;
$$;
