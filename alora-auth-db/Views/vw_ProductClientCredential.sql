/****** Object: View [vw_ProductClientCredential] ******/
-- The one projection that carries a product's secret hash, consumed only by
-- client authentication at the token endpoint.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE VIEW vw_ProductClientCredential AS
SELECT p.id,
       p.key,
       p.is_active,
       p.client_secret_hash
FROM   tbl_products p
WHERE  p.client_secret_hash IS NOT NULL;
