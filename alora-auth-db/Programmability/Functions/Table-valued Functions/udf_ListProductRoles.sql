/****** Object: Table-valued Function [udf_ListProductRoles] ******/
-- A product's role catalogue.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_ListProductRoles(p_productId TEXT)
RETURNS SETOF tbl_product_roles
LANGUAGE sql
STABLE
AS $$
    SELECT * FROM tbl_product_roles r WHERE r.product_id = p_productId ORDER BY r.role_name;
$$;
