/****** Object: View [vw_SessionSummary] ******/
-- The admin session-list row. Carries the 'active' predicate, and
-- deliberately omits refresh_token_hash, prev_token_hash, revoked_reason and
-- user_id — the columns the response contract bans. A leak here would hand
-- an admin (or an XSS payload reading the page) material capable of
-- impersonation.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE VIEW vw_SessionSummary AS
SELECT s.id,
       s.client_id,
       s.device_label,
       s.ip_address,
       s.last_seen_at,
       s.created_at
FROM   tbl_user_sessions s
WHERE  s.revoked_at IS NULL
  AND  s.expires_at  > now();
