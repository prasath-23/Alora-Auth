/****** Object: View [vw_UserCredential] ******/
-- The login projection. This is the ONLY view that exposes password_hash,
-- and it is consumed by exactly one function (the candidate lookup).
-- Restricted to live, password-capable accounts in ACTIVE tenants, so a
-- deleted, disabled or OAuth-only user -- or anyone in a suspended
-- organisation -- can never be authenticated by password.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE VIEW vw_UserCredential AS
SELECT u.id,
       u.client_id,
       u.email,
       u.password_hash,
       u.account_type,
       u.created_at
FROM   tbl_users u
JOIN   tbl_clients c ON c.id = u.client_id
                    AND c.is_active = true
WHERE  u.deleted_at    IS NULL
  AND  u.is_active      = true
  AND  u.account_type  IN ('EMAIL', 'HYBRID')
  AND  u.password_hash IS NOT NULL;
