/****** Object: Scalar-valued Function [udf_ActiveSubscriptionId] ******/
-- The tenant's live subscription to a product, or NULL. The grant paths gate
-- on this, so a tenant cannot be granted a role in a product it does not pay
-- for.
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
      AND  cp.starts_at  <= now()
      AND  (cp.ends_at   IS NULL OR cp.ends_at > now())
    LIMIT  1;
$$;
