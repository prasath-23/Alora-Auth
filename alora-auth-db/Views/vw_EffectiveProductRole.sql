/****** Object: View [vw_EffectiveProductRole] ******/
-- EVERY role a user holds in a product: direct grants inside their validity
-- window, plus the roles of the groups they belong to -- and only where the
-- user, their tenant and the product are active and the tenant's
-- subscription is live. This is the single definition of 'may use this
-- product'; the launch check, the token's roles claim and the app list all
-- read it.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE VIEW vw_EffectiveProductRole AS
SELECT r.user_id,
       r.client_id,
       r.product_id,
       p.key        AS product_key,
       p.name       AS product_name,
       r.role_name,
       r.source,
       r.group_id
FROM   (SELECT pp.user_id, pp.client_id, pp.product_id, pp.role_name,
               'DIRECT'::text AS source, NULL::text AS group_id
        FROM   tbl_product_permissions pp
        WHERE  pp.valid_from <= now()
          AND  (pp.valid_until IS NULL OR pp.valid_until > now())
        UNION ALL
        SELECT ug.user_id, g.client_id, gpg.product_id, gpg.role_name,
               'GROUP'::text AS source, g.id AS group_id
        FROM   tbl_group_product_grants gpg
        JOIN   tbl_groups      g  ON g.id  = gpg.group_id
                                 AND g.client_id = gpg.client_id
        JOIN   tbl_user_groups ug ON ug.group_id  = g.id
                                 AND ug.client_id = g.client_id) r
JOIN   tbl_users           u  ON u.id = r.user_id
                             AND u.client_id  = r.client_id
                             AND u.deleted_at IS NULL
                             AND u.is_active  = true
JOIN   tbl_clients         c  ON c.id = r.client_id
                             AND c.is_active  = true
JOIN   tbl_products        p  ON p.id = r.product_id
                             AND p.is_active  = true
JOIN   tbl_client_products cp ON cp.client_id  = r.client_id
                             AND cp.product_id = r.product_id
                             AND cp.is_active  = true
                             AND cp.starts_at <= now()
                             AND (cp.ends_at IS NULL OR cp.ends_at > now());
