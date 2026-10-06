/****** Object: View [vw_ProductClient] ******/
-- A product's registration as an OAuth client, WITHOUT its secret hash: only
-- whether one is set.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE VIEW vw_ProductClient AS
SELECT p.id,
       p.key,
       p.name,
       p.description,
       p.base_url,
       p.initiate_login_uri,
       p.is_active,
       p.accepts_api_clients,
       (p.client_secret_hash IS NOT NULL)::boolean AS has_secret,
       p.secret_rotated_at,
       p.created_at,
       p.updated_at
FROM   tbl_products p;
