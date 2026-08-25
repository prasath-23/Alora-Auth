/****** Object: Scalar-valued Function [udf_ActiveSubscriptionId] ******/
-- The tenant's live subscription to a product, or NULL. Both the login path
-- and the permission-grant path gate on this, so a tenant cannot be signed
-- into (or granted a role in) a product it does not pay for.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_ActiveSubscriptionId(p_clientId TEXT, p_productId TEXT)
RETURNS TEXT
LANGUAGE sql
STABLE
AS $$
    SELECT cp.id
    FROM   tbl_client_products cp
    WHERE  cp.client_id  = p_clientId
      AND  cp.product_id = p_productId
      AND  cp.is_active   = true
      AND  (cp.ends_at   IS NULL OR cp.ends_at > now())
    LIMIT  1;
$$;
