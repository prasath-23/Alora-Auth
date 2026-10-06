/****** Object: View [vw_SsoConnectionRuntime] ******/
-- What the SSO login path needs, including the encrypted secret. is_active
-- also covers the tenant, so a suspended organisation's connection cannot be
-- used.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE VIEW vw_SsoConnectionRuntime AS
SELECT sc.id,
       sc.client_id,
       sc.name,
       sc.issuer,
       sc.oidc_client_id,
       sc.client_secret_ciphertext,
       sc.secret_key_id,
       sc.scopes,
       sc.trust_unverified_email,
       (sc.is_active AND c.is_active)::boolean AS is_active,
       COALESCE((SELECT array_agg(d.domain ORDER BY d.domain)
                 FROM   tbl_sso_connection_domains d
                 WHERE  d.connection_id = sc.id), '{}')::text[] AS domains
FROM   tbl_sso_connections sc
JOIN   tbl_clients c ON c.id = sc.client_id;
