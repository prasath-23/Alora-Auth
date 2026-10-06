/****** Object: View [vw_UserProductRole] ******/
-- A user's DIRECT product-role grants inside their validity window, with the
-- product resolved. Effective access, which also counts group grants, is
-- vw_EffectiveProductRole.
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
WHERE  pp.valid_from <= now()
  AND  (pp.valid_until IS NULL OR pp.valid_until > now());
