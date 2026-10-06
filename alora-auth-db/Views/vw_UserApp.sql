/****** Object: View [vw_UserApp] ******/
-- One row per product a user may open, with every role they hold in it: what
-- App Central's launcher shows.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE VIEW vw_UserApp AS
SELECT e.user_id,
       e.client_id,
       e.product_id,
       p.key                AS product_key,
       p.name               AS product_name,
       p.description        AS product_description,
       p.base_url,
       p.initiate_login_uri,
       array_agg(DISTINCT e.role_name ORDER BY e.role_name)::text[] AS roles
FROM   vw_EffectiveProductRole e
JOIN   tbl_products p ON p.id = e.product_id
GROUP  BY e.user_id, e.client_id, e.product_id, p.key, p.name, p.description,
          p.base_url, p.initiate_login_uri;
