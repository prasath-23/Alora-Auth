/****** Object: View [vw_UserProductRole] ******/
-- Active product-role grants. The validity window is part of the view, so an
-- expired grant cannot leak into a JWT roles claim from any caller. Inner
-- join to products is loss-free because the product FK is RESTRICT.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE VIEW vw_UserProductRole AS
SELECT pp.user_id,
       pp.client_id,
       pp.product_id,
       p.key        AS product_key,
       p.name       AS product_name,
       pp.role_name,
       pp.valid_until
FROM   tbl_product_permissions pp
JOIN   tbl_products p ON p.id = pp.product_id
WHERE  pp.valid_until IS NULL
   OR  pp.valid_until  > now();
