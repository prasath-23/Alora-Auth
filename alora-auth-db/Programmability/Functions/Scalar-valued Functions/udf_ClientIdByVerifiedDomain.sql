/****** Object: Scalar-valued Function [udf_ClientIdByVerifiedDomain] ******/
-- Resolves a hostname to its tenant, but ONLY for a verified domain on an
-- active tenant. This backs the CORS decision and the federated-login tenant
-- lookup, so requiring verification is what stops someone claiming an
-- unowned domain and being admitted to another organisation.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_ClientIdByVerifiedDomain(p_domain TEXT)
RETURNS TEXT
LANGUAGE sql
STABLE
AS $$
    SELECT c.id
    FROM   tbl_clients c
    WHERE  lower(c.domain)      = lower(p_domain)
      AND  c.domain_verified_at IS NOT NULL
      AND  c.is_active           = true
    LIMIT  1;
$$;
