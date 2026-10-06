/****** Object: View [vw_UserTenantScoped] ******/
-- A single live member of a tenant, as the admin surface sees them. is_admin
-- is membership of the tenant's ADMINS system group, evaluated live. Omits
-- password_hash and deleted_at (the latter is implied by the predicate).
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE VIEW vw_UserTenantScoped AS
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
