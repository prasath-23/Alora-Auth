/****** Object: Stored Procedure [stp_SetClientDomain] ******/
-- Sets a tenant's email domain, and whether an Owner has verified it. A
-- verified domain already held by another tenant raises 23505.
--
-- Implemented as a FUNCTION, not a PROCEDURE: the caller needs the result,
-- and PostgreSQL procedures cannot return a result set.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_SetClientDomain(p_clientId TEXT, p_domain TEXT, p_verified BOOLEAN)
RETURNS SETOF tbl_clients
LANGUAGE sql
VOLATILE
AS $$
    UPDATE tbl_clients
    SET    domain             = lower(p_domain),
           domain_verified_at = CASE WHEN p_verified AND p_domain IS NOT NULL THEN now() ELSE NULL END,
           updated_at         = now()
    WHERE  id = p_clientId
    RETURNING *;
$$;
