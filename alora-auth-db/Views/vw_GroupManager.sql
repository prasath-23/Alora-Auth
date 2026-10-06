/****** Object: View [vw_GroupManager] ******/
-- A group's managers, each with their address and who appointed them (a user
-- of the tenant, or an Owner). Soft-deleted people are left out in the
-- WHERE, so a deleted manager's id is never disclosed either.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE VIEW vw_GroupManager AS
SELECT gm.group_id,
       gm.client_id,
       gm.user_id,
       u.email,
       gm.appointed_at,
       COALESCE(au.email, ao.email, '')               AS appointed_by_email,
       (gm.appointed_by_owner_id IS NOT NULL)::boolean AS appointed_by_owner
FROM   tbl_group_managers gm
JOIN   tbl_users u        ON u.id         = gm.user_id
                         AND u.client_id  = gm.client_id
LEFT   JOIN tbl_users au  ON au.id        = gm.appointed_by_user_id
                         AND au.client_id = gm.client_id
LEFT   JOIN tbl_users ao  ON ao.id        = gm.appointed_by_owner_id
WHERE  u.deleted_at IS NULL;
