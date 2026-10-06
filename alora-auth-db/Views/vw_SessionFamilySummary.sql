/****** Object: View [vw_SessionFamilySummary] ******/
-- The admin session list: one row per live login, with whose it is (by
-- address) and its latest generation's device details. Deliberately omits
-- every token hash and the user id -- the columns the response contract
-- bans.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE VIEW vw_SessionFamilySummary AS
SELECT f.id,
       f.client_id,
       f.kind,
       p.key                        AS product_key,
       f.auth_method,
       f.authenticated_at,
       f.created_at,
       COALESCE(s.device_label, '')::text AS device_label,
       COALESCE(s.ip_address, '')::text   AS ip_address,
       s.last_seen_at::timestamptz  AS last_seen_at,
       u.email
FROM   tbl_session_families f
JOIN   tbl_users u ON u.id = f.user_id
                  AND u.client_id = f.client_id
LEFT   JOIN tbl_products p ON p.id = f.product_id
JOIN   LATERAL (SELECT ls.device_label, ls.ip_address, ls.last_seen_at
                FROM   tbl_user_sessions ls
                WHERE  ls.family_id  = f.id
                  AND  ls.revoked_at IS NULL
                  AND  ls.expires_at > now()
                ORDER  BY ls.generation DESC
                LIMIT  1) s ON true
WHERE  f.revoked_at IS NULL
  AND  f.absolute_expires_at > now();
