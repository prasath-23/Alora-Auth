/****** Object: View [vw_GroupDetailRow] ******/
-- One row per group member, or a single row with NULL member columns for an
-- empty group (LEFT JOIN). The group's own columns repeat on every row; the
-- caller takes them from the first. Soft-deleted users are excluded, so
-- their addresses are never disclosed through the group detail endpoint.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE VIEW vw_GroupDetailRow AS
SELECT g.id,
       g.client_id,
       g.name,
       g.description,
       g.system_key,
       g.login_policy_id,
       g.created_at,
       CASE WHEN g.system_key = 'ADMINS'
            THEN (SELECT jsonb_agg(s.scope ORDER BY s.scope)
                  FROM   tbl_scopes s
                  WHERE  s.kind = 'PERSON')
            ELSE COALESCE((SELECT jsonb_agg(gs.scope ORDER BY gs.scope)
                           FROM   tbl_group_scopes gs
                           WHERE  gs.group_id  = g.id
                             AND  gs.client_id = g.client_id), '[]'::jsonb)
       END AS scopes,
       COALESCE((SELECT jsonb_agg(jsonb_build_object('product_id', gpg.product_id,
                                                     'product_key', pr.key,
                                                     'role_name', gpg.role_name)
                                  ORDER BY pr.key)
                 FROM   tbl_group_product_grants gpg
                 JOIN   tbl_products pr ON pr.id = gpg.product_id
                 WHERE  gpg.group_id  = g.id
                   AND  gpg.client_id = g.client_id), '[]'::jsonb) AS product_grants,
       ug.user_id,
       u.email       AS user_email,
       ug.assigned_at
FROM   tbl_groups g
LEFT   JOIN tbl_user_groups ug ON ug.group_id  = g.id
                              AND ug.client_id = g.client_id
LEFT   JOIN tbl_users u        ON u.id         = ug.user_id
                              AND u.client_id  = g.client_id
                              AND u.deleted_at IS NULL;
