/****** Object: Table-valued Function [udf_ListProductRedirectUris] ******/
-- A product's registered redirect URIs.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_ListProductRedirectUris(p_productId TEXT)
RETURNS SETOF tbl_product_redirect_uris
LANGUAGE sql
STABLE
AS $$
    SELECT * FROM tbl_product_redirect_uris r WHERE r.product_id = p_productId ORDER BY r.redirect_uri;
$$;
