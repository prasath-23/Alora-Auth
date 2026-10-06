/****** Object: View [vw_SsoConnectionSummary] ******/
-- An SSO connection as the Owner console shows it: never the secret, only
-- whether one is set.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE VIEW vw_SsoConnectionSummary AS
SELECT sc.id,
       sc.client_id,
       sc.name,
       sc.issuer,
       sc.oidc_client_id,
       sc.scopes,
       sc.trust_unverified_email,
       sc.is_active,
       (sc.client_secret_ciphertext IS NOT NULL)::boolean AS has_secret,
       COALESCE((SELECT array_agg(d.domain ORDER BY d.domain)
                 FROM   tbl_sso_connection_domains d
                 WHERE  d.connection_id = sc.id), '{}')::text[] AS domains,
       sc.created_at,
       sc.updated_at
FROM   tbl_sso_connections sc;
