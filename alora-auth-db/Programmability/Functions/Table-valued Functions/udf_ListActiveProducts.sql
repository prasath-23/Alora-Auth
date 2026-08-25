/****** Object: Table-valued Function [udf_ListActiveProducts] ******/
-- The active product catalogue. Global, not tenant-scoped: the catalogue is
-- platform-wide and carries no tenant data.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_ListActiveProducts()
RETURNS SETOF tbl_products
LANGUAGE sql
STABLE
AS $$
    SELECT * FROM tbl_products p WHERE p.is_active = true ORDER BY p.name;
$$;
