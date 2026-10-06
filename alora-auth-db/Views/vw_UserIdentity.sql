/****** Object: View [vw_UserIdentity] ******/
-- The token-minting projection: everything a token payload needs and nothing
-- more. The liveness predicate -- the user AND their tenant -- is part of
-- the view, so an account or organisation disabled mid-flow cannot be minted
-- a token. Deliberately excludes password_hash.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE VIEW vw_UserIdentity AS
SELECT u.id,
       u.client_id,
       u.email,
       u.permissions_version
FROM   tbl_users u
JOIN   tbl_clients c ON c.id = u.client_id
                    AND c.is_active = true
WHERE  u.deleted_at IS NULL
  AND  u.is_active   = true;
