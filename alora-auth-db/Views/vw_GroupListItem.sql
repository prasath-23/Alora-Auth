/****** Object: View [vw_GroupListItem] ******/
-- Group list with its feature keys aggregated and its live member count. The
-- count joins tbl_users so soft-deleted members are excluded — otherwise the
-- group list would report a total that contradicts the user list.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE VIEW vw_GroupListItem AS
SELECT g.id,
       g.client_id,
       g.name,
       g.description,
       g.created_at,
       g.updated_at,
       COALESCE((SELECT jsonb_agg(gf.feature_key ORDER BY gf.feature_key)
                 FROM   tbl_group_features gf
                 WHERE  gf.group_id = g.id), '[]'::jsonb) AS features,
       (SELECT count(*)
        FROM   tbl_user_groups ug
        JOIN   tbl_users mu ON mu.id = ug.user_id
                           AND mu.deleted_at IS NULL
        WHERE  ug.group_id  = g.id
          AND  ug.client_id = g.client_id)::bigint        AS member_count
FROM   tbl_groups g;
