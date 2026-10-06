/****** Object: View [vw_UserListItem] ******/
-- The admin user-list row. Same shape as vw_UserTenantScoped but kept
-- separate because the two are consumed by different endpoints and will
-- diverge: a change to the list must not silently alter the detail lookup.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE VIEW vw_UserListItem AS
SELECT u.id,
       u.client_id,
       u.email,
       u.account_type,
       u.is_active,
       u.permissions_version,
       u.login_policy_id,
       EXISTS (SELECT 1
               FROM   tbl_user_groups ug
               JOIN   tbl_groups g ON g.id = ug.group_id
                                  AND g.client_id = ug.client_id
               WHERE  ug.user_id    = u.id
                 AND  ug.client_id  = u.client_id
                 AND  g.system_key  = 'ADMINS')::boolean AS is_admin,
       u.created_at,
       u.updated_at,
       EXISTS (SELECT 1 FROM tbl_platform_owners po
               WHERE  po.user_id   = u.id
                 AND  po.client_id = u.client_id)::boolean AS is_owner
FROM   tbl_users u
WHERE  u.deleted_at IS NULL;
