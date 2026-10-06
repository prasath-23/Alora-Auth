/****** Object: View [vw_ApiClientSummary] ******/
-- An API client with its company's name, its scopes (sorted by name, as a
-- token lists them), the products on its list -- each marked usable while
-- its subscription is live, the product is active and it accepts API clients
-- -- and how many live secrets it has. Never a secret hash.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE VIEW vw_ApiClientSummary AS
SELECT a.id,
       a.client_id,
       c.name AS company_name,
       a.name,
       a.description,
       a.is_active,
       a.created_by_user_id,
       a.created_by_owner_id,
       a.last_used_at,
       a.created_at,
       a.updated_at,
       COALESCE((SELECT jsonb_agg(s.scope ORDER BY s.scope)
                 FROM   tbl_api_client_scopes s
                 WHERE  s.api_client_id = a.id
                   AND  s.client_id     = a.client_id), '[]'::jsonb) AS scopes,
       COALESCE((SELECT jsonb_agg(jsonb_build_object(
                            'product_id',   p.id,
                            'product_key',  p.key,
                            'product_name', p.name,
                            'usable',       cp.is_active AND cp.starts_at <= now()
                                            AND (cp.ends_at IS NULL OR cp.ends_at > now())
                                            AND p.is_active AND p.accepts_api_clients)
                        ORDER BY p.key)
                 FROM   tbl_api_client_products ap
                 JOIN   tbl_products        p  ON p.id = ap.product_id
                 JOIN   tbl_client_products cp ON cp.client_id  = ap.client_id
                                              AND cp.product_id = ap.product_id
                 WHERE  ap.api_client_id = a.id
                   AND  ap.client_id     = a.client_id), '[]'::jsonb) AS products,
       (SELECT count(*)
        FROM   tbl_api_client_secrets x
        WHERE  x.api_client_id = a.id
          AND  x.client_id     = a.client_id
          AND  x.revoked_at IS NULL
          AND  (x.expires_at IS NULL OR x.expires_at > now()))::int AS live_secrets
FROM   tbl_api_clients a
JOIN   tbl_clients     c ON c.id = a.client_id;
