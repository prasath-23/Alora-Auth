/****** Object: View [vw_ApiClientGrant] ******/
-- What the client-credentials grant checks for one API client and one
-- product on its list: whether a token may be issued right now -- the client
-- and its company active, the subscription live, the product active and
-- accepting API clients -- and the scopes the client holds. A product not on
-- the list has no row.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE VIEW vw_ApiClientGrant AS
SELECT a.id      AS api_client_id,
       a.client_id,
       p.id      AS product_id,
       p.key     AS product_key,
       (a.is_active AND c.is_active
        AND cp.is_active AND cp.starts_at <= now() AND (cp.ends_at IS NULL OR cp.ends_at > now())
        AND p.is_active AND p.accepts_api_clients)::boolean AS usable,
       ARRAY(SELECT s.scope
             FROM   tbl_api_client_scopes s
             WHERE  s.api_client_id = a.id
               AND  s.client_id     = a.client_id
             ORDER  BY s.scope)::text[] AS scopes
FROM   tbl_api_client_products ap
JOIN   tbl_api_clients     a  ON a.id = ap.api_client_id
                             AND a.client_id = ap.client_id
JOIN   tbl_clients         c  ON c.id = a.client_id
JOIN   tbl_products        p  ON p.id = ap.product_id
JOIN   tbl_client_products cp ON cp.client_id  = ap.client_id
                             AND cp.product_id = ap.product_id;
