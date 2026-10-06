/****** Object: View [vw_ApiClientSecret] ******/
-- An API client's secrets WITHOUT their hashes: enough to tell them apart
-- and to see which are live. A secret is live until it is revoked or
-- expires.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE VIEW vw_ApiClientSecret AS
SELECT x.id,
       x.api_client_id,
       x.client_id,
       x.prefix,
       x.expires_at,
       x.revoked_at,
       x.last_used_at,
       x.created_by_user_id,
       x.created_by_owner_id,
       x.created_at,
       (x.revoked_at IS NULL AND (x.expires_at IS NULL OR x.expires_at > now()))::boolean AS is_live
FROM   tbl_api_client_secrets x;
