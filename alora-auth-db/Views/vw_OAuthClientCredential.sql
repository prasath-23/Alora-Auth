/****** Object: View [vw_OAuthClientCredential] ******/
-- The ONE client-authentication projection for the token endpoint, carrying
-- secret hashes: a product's secret, or each live secret of an API client
-- (so 0-2 rows for one client id). Columns that do not apply to a kind are
-- empty strings, never NULL, so every column has one type. is_active folds
-- in what makes a client unusable outright: a product switched off, or an
-- API client -- or its company -- switched off.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE VIEW vw_OAuthClientCredential AS
SELECT 'PRODUCT'::text      AS kind,
       p.id                 AS oauth_client_id,
       p.key                AS product_key,
       ''::text             AS company_id,
       ''::text             AS secret_id,
       p.client_secret_hash AS secret_hash,
       p.is_active          AS is_active
FROM   tbl_products p
WHERE  p.client_secret_hash IS NOT NULL
UNION  ALL
SELECT 'API_CLIENT'::text,
       a.id,
       ''::text,
       a.client_id,
       x.id,
       x.secret_hash,
       (a.is_active AND c.is_active)::boolean
FROM   tbl_api_clients a
JOIN   tbl_clients            c ON c.id = a.client_id
JOIN   tbl_api_client_secrets x ON x.api_client_id = a.id
                               AND x.client_id     = a.client_id
WHERE  x.revoked_at IS NULL
  AND  (x.expires_at IS NULL OR x.expires_at > now());
