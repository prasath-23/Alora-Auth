/****** Object: Table-valued Function [udf_ListScopes] ******/
-- The scope catalogue, in display order.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_ListScopes()
RETURNS SETOF tbl_scopes
LANGUAGE sql
STABLE
AS $$
    SELECT * FROM tbl_scopes s ORDER BY s.sort_order;
$$;
