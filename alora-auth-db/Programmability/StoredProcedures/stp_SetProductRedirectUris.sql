/****** Object: Stored Procedure [stp_SetProductRedirectUris] ******/
-- Replaces a product's redirect URIs wholesale with the complete desired
-- set.
--
-- Implemented as a FUNCTION, not a PROCEDURE: the caller needs the result,
-- and PostgreSQL procedures cannot return a result set.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_SetProductRedirectUris(p_productId TEXT, p_redirectUris TEXT[])
RETURNS INTEGER
LANGUAGE sql
VOLATILE
AS $$
    DELETE FROM tbl_product_redirect_uris WHERE product_id = p_productId;
    INSERT INTO tbl_product_redirect_uris (product_id, redirect_uri)
    SELECT DISTINCT p_productId, u FROM unnest(p_redirectUris) AS u;
    SELECT count(*)::int FROM tbl_product_redirect_uris WHERE product_id = p_productId;
$$;
