/****** Object: Table-valued Function [udf_ListProducts] ******/
-- The whole catalogue with registration details, for the Owner console.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_ListProducts()
RETURNS SETOF vw_ProductClient
LANGUAGE sql
STABLE
AS $$
    SELECT * FROM vw_ProductClient v ORDER BY v.name;
$$;
