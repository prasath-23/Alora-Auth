/****** Object: View [vw_UserIdentity] ******/
-- The token-minting projection: everything a JWT payload needs and nothing
-- more. The liveness predicate is part of the view, so an account
-- deactivated between issuing an authorization code and redeeming it cannot
-- be minted a token. Deliberately excludes password_hash.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE VIEW vw_UserIdentity AS
SELECT u.id,
       u.client_id,
       u.email,
       u.is_global_admin,
       u.permissions_version
FROM   tbl_users u
WHERE  u.deleted_at IS NULL
  AND  u.is_active   = true;
