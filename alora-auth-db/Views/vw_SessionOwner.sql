/****** Object: View [vw_SessionOwner] ******/
-- Minimal session identity for the logout and admin-revoke paths: enough to
-- decide whether to act, with no token material.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE VIEW vw_SessionOwner AS
SELECT s.id,
       s.user_id,
       s.client_id,
       s.revoked_at,
       s.refresh_token_hash
FROM   tbl_user_sessions s;
