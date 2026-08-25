/****** Object: View [vw_UserCredential] ******/
-- The login projection. This is the ONLY view that exposes password_hash,
-- and it is consumed by exactly one function (the credential check).
-- Restricted to live, password-capable accounts, so a deleted, disabled or
-- OAuth-only user can never be authenticated by password.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE VIEW vw_UserCredential AS
SELECT u.id,
       u.client_id,
       u.email,
       u.password_hash,
       u.account_type,
       u.is_global_admin,
       u.permissions_version
FROM   tbl_users u
WHERE  u.deleted_at   IS NULL
  AND  u.is_active     = true
  AND  u.account_type IN ('EMAIL', 'HYBRID');
