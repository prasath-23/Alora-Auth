/****** Object: View [vw_DomainLoginHint] ******/
-- Login discovery by email DOMAIN, never by account: a domain attested for
-- an active SSO connection routes to it; a tenant's verified domain offers
-- that tenant's default methods. Answers depend on the domain alone, so
-- discovery cannot reveal whether an account exists.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE VIEW vw_DomainLoginHint AS
SELECT lower(c.domain)       AS domain,
       c.id                  AS client_id,
       NULL::text            AS connection_id,
       dp.allow_password,
       dp.allow_google
FROM   tbl_clients c
JOIN   tbl_login_policies dp ON dp.client_id = c.id
                            AND dp.is_default
WHERE  c.domain IS NOT NULL
  AND  c.domain_verified_at IS NOT NULL
  AND  c.is_active = true
  AND  NOT EXISTS (SELECT 1 FROM tbl_sso_connection_domains x
                   WHERE  x.domain = lower(c.domain))
UNION  ALL
SELECT d.domain,
       d.client_id,
       d.connection_id,
       dp.allow_password,
       dp.allow_google
FROM   tbl_sso_connection_domains d
JOIN   tbl_sso_connections sc ON sc.id = d.connection_id
                             AND sc.client_id = d.client_id
                             AND sc.is_active = true
JOIN   tbl_clients         c  ON c.id = d.client_id
                             AND c.is_active  = true
JOIN   tbl_login_policies  dp ON dp.client_id = d.client_id
                             AND dp.is_default;
