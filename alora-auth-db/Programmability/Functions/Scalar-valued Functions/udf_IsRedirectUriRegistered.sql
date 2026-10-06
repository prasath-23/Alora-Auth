/****** Object: Scalar-valued Function [udf_IsRedirectUriRegistered] ******/
-- TRUE only for an EXACT match against an active product's registered
-- redirect URIs. No prefix, origin or wildcard matching: any of those is an
-- open redirect waiting to happen.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_IsRedirectUriRegistered(p_productId TEXT, p_redirectUri TEXT)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM   tbl_product_redirect_uris r
        JOIN   tbl_products p ON p.id = r.product_id
                             AND p.is_active = true
        WHERE  r.product_id   = p_productId
          AND  r.redirect_uri = p_redirectUri
    );
$$;
