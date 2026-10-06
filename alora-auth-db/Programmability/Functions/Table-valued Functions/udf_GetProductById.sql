/****** Object: Table-valued Function [udf_GetProductById] ******/
-- A product, optionally restricted to active ones.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_GetProductById(p_productId TEXT, p_activeOnly BOOLEAN DEFAULT false)
RETURNS SETOF tbl_products
LANGUAGE sql
STABLE
AS $$
    SELECT * FROM tbl_products p
    WHERE  p.id = p_productId
      AND  (p_activeOnly = false OR p.is_active = true);
$$;
