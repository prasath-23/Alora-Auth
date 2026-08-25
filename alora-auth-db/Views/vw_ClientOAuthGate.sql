/****** Object: View [vw_ClientOAuthGate] ******/
-- The per-tenant identity-provider policy, used to decide whether a
-- federated login may proceed at all.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE VIEW vw_ClientOAuthGate AS
SELECT c.id,
       c.allowed_idp_providers,
       c.is_active
FROM   tbl_clients c;
