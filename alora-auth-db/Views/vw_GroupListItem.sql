/****** Object: View [vw_GroupListItem] ******/
-- Group list with its scopes (sorted by name, as a token lists them),
-- product grants and live member count. The count joins tbl_users so
-- soft-deleted members are excluded -- otherwise the group list would report
-- a total that contradicts the user list.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE VIEW vw_GroupListItem AS
SELECT g.id,
       g.client_id,
       g.name,
       g.description,
       g.system_key,
       g.login_policy_id,
       g.created_at,
       g.updated_at,
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
       (SELECT count(*)
        FROM   tbl_user_groups ug
        JOIN   tbl_users mu ON mu.id = ug.user_id
                           AND mu.deleted_at IS NULL
        WHERE  ug.group_id  = g.id
          AND  ug.client_id = g.client_id)::bigint        AS member_count
FROM   tbl_groups g;
