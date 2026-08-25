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
       u.is_global_admin,
       u.permissions_version,
       u.created_at,
       u.updated_at
FROM   tbl_users u
WHERE  u.deleted_at IS NULL;
