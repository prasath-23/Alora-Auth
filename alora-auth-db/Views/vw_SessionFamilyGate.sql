/****** Object: View [vw_SessionFamilyGate] ******/
-- Everything a refresh, a launch or an authenticated request must know about
-- one login, in one row. A family is alive only while it is unrevoked,
-- inside its absolute cap AND has a live generation; a product family
-- additionally needs a live parent and effective access to its product.
-- scopes is the person's effective App Central scope set, read fresh on
-- every request.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE VIEW vw_SessionFamilyGate AS
SELECT f.id                       AS family_id,
       f.user_id,
       f.client_id,
       f.kind,
       f.product_id,
       f.parent_family_id,
       f.auth_method,
       f.auth_connection_id,
       f.authenticated_at,
       f.absolute_expires_at,
       (f.revoked_at IS NULL
        AND f.absolute_expires_at > now()
        AND EXISTS (SELECT 1 FROM tbl_user_sessions s
                    WHERE  s.family_id  = f.id
                      AND  s.revoked_at IS NULL
                      AND  s.expires_at > now()))::boolean AS family_alive,
       (f.parent_family_id IS NULL
        OR (pf.revoked_at IS NULL
            AND pf.absolute_expires_at > now()
            AND EXISTS (SELECT 1 FROM tbl_user_sessions ps
                        WHERE  ps.family_id  = pf.id
                          AND  ps.revoked_at IS NULL
                          AND  ps.expires_at > now())))::boolean AS parent_alive,
       (u.is_active AND u.deleted_at IS NULL)::boolean AS user_active,
       c.is_active                                     AS client_active,
       u.email,
       u.permissions_version,
       EXISTS (SELECT 1
               FROM   tbl_user_groups ug
               JOIN   tbl_groups g ON g.id = ug.group_id
                                  AND g.client_id = ug.client_id
               WHERE  ug.user_id   = f.user_id
                 AND  ug.client_id = f.client_id
                 AND  g.system_key = 'ADMINS')::boolean AS is_tenant_admin,
       EXISTS (SELECT 1 FROM tbl_platform_owners po
               WHERE  po.user_id   = f.user_id
                 AND  po.client_id = f.client_id)::boolean AS is_platform_owner,
       (f.product_id IS NULL
        OR EXISTS (SELECT 1 FROM vw_EffectiveProductRole e
                   WHERE  e.user_id    = f.user_id
                     AND  e.client_id  = f.client_id
                     AND  e.product_id = f.product_id))::boolean AS has_access,
       u.admin_version,
       ARRAY(SELECT DISTINCT es.scope
             FROM   vw_EffectiveScope es
             WHERE  es.user_id   = f.user_id
               AND  es.client_id = f.client_id
             ORDER  BY es.scope)::text[] AS scopes
FROM   tbl_session_families f
JOIN   tbl_users   u  ON u.id = f.user_id
                     AND u.client_id = f.client_id
JOIN   tbl_clients c  ON c.id = f.client_id
LEFT   JOIN tbl_session_families pf ON pf.id = f.parent_family_id;
