/****** Object: View [vw_ClientProductDetail] ******/
-- A tenant's subscriptions with the product resolved. Shaped to match the
-- response contract exactly: id is the SUBSCRIPTION id, not the product id.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE VIEW vw_ClientProductDetail AS
SELECT cp.id,
       cp.client_id,
       cp.product_id,
       cp.is_active,
       cp.seat_limit,
       cp.starts_at,
       cp.ends_at,
       cp.created_at,
       p.key         AS product_key,
       p.name        AS product_name,
       p.description AS product_description,
       p.base_url    AS product_base_url,
       p.is_active   AS product_is_active
FROM   tbl_client_products cp
JOIN   tbl_products p ON p.id = cp.product_id;
