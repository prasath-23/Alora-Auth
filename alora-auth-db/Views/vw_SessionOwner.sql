/****** Object: View [vw_SessionOwner] ******/
-- Minimal session identity for the logout paths: enough to find the family
-- to revoke, with no token material beyond the hash already presented.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE VIEW vw_SessionOwner AS
SELECT s.id,
       s.family_id,
       s.user_id,
       s.client_id,
       s.revoked_at,
       s.refresh_token_hash
FROM   tbl_user_sessions s;
