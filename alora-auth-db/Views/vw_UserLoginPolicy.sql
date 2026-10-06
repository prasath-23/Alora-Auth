/****** Object: View [vw_UserLoginPolicy] ******/
-- The login policy that applies to each live user: their own assignment,
-- else the highest-priority policy among their groups, else the tenant
-- default. Every sign-in path and every refresh enforces this row, never
-- only the UI.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE VIEW vw_UserLoginPolicy AS
SELECT u.id                                  AS user_id,
       u.client_id,
       p.id                                  AS policy_id,
       p.name                                AS policy_name,
       p.allow_password,
       p.allow_google,
       p.sso_connection_id,
       (CASE WHEN u.login_policy_id IS NOT NULL THEN 'USER'
             WHEN gp.policy_id      IS NOT NULL THEN 'GROUP'
             ELSE 'DEFAULT' END)::text        AS source
FROM   tbl_users u
LEFT   JOIN LATERAL (
       SELECT lp.id AS policy_id
       FROM   tbl_user_groups    ug
       JOIN   tbl_groups         g  ON g.id  = ug.group_id
                                   AND g.client_id = ug.client_id
       JOIN   tbl_login_policies lp ON lp.id = g.login_policy_id
                                   AND lp.client_id = g.client_id
       WHERE  ug.user_id   = u.id
         AND  ug.client_id = u.client_id
       ORDER  BY lp.priority DESC
       LIMIT  1) gp ON true
JOIN   tbl_login_policies p ON p.client_id = u.client_id
                           AND p.id = COALESCE(u.login_policy_id, gp.policy_id,
                                               (SELECT d.id FROM tbl_login_policies d
                                                WHERE  d.client_id = u.client_id
                                                  AND  d.is_default))
WHERE  u.deleted_at IS NULL;
