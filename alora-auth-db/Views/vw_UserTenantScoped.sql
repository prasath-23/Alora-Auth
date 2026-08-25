/****** Object: View [vw_UserTenantScoped] ******/
-- A single live member of a tenant, as the admin surface sees them. Omits
-- password_hash and deleted_at (the latter is implied by the predicate).
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE VIEW vw_UserTenantScoped AS
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
