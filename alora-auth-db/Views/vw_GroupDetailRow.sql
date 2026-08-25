/****** Object: View [vw_GroupDetailRow] ******/
-- One row per group member, or a single row with NULL member columns for an
-- empty group (LEFT JOIN). The feature list repeats on every row; the caller
-- takes it from the first. Soft-deleted users are excluded, so their
-- addresses are never disclosed through the group detail endpoint.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE VIEW vw_GroupDetailRow AS
SELECT g.id,
       g.client_id,
       g.name,
       g.description,
       g.created_at,
       COALESCE((SELECT jsonb_agg(gf.feature_key ORDER BY gf.feature_key)
                 FROM   tbl_group_features gf
                 WHERE  gf.group_id = g.id), '[]'::jsonb) AS features,
       ug.user_id,
       u.email       AS user_email,
       ug.assigned_at
FROM   tbl_groups g
LEFT   JOIN tbl_user_groups ug ON ug.group_id  = g.id
                              AND ug.client_id = g.client_id
LEFT   JOIN tbl_users u        ON u.id         = ug.user_id
                              AND u.client_id  = g.client_id
                              AND u.deleted_at IS NULL;
