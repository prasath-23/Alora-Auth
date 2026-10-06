/****** Object: Stored Procedure [stp_SetSsoConnectionDomains] ******/
-- Replaces the email domains routed to a connection, wholesale.
--
-- Refuses (-2) a domain that ANOTHER tenant has verified: attaching it here would
-- route that tenant's users' sign-ins to this tenant's identity provider. A
-- domain already attached to another connection raises 23505 on the primary key.
-- Returns -1 for a connection outside the tenant.
--
-- Implemented as a FUNCTION: the caller needs the outcome.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_SetSsoConnectionDomains(
    p_connectionId TEXT,
    p_clientId     TEXT,
    p_domains      TEXT[]
)
RETURNS INTEGER
LANGUAGE plpgsql
VOLATILE
AS $$
DECLARE
    v_inserted INTEGER := 0;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM tbl_sso_connections
                   WHERE  id = p_connectionId AND client_id = p_clientId) THEN
        RETURN -1;
    END IF;

    IF EXISTS (SELECT 1 FROM tbl_clients c
               WHERE  c.id <> p_clientId
                 AND  c.domain_verified_at IS NOT NULL
                 AND  lower(c.domain) IN (SELECT lower(d) FROM unnest(p_domains) AS d)) THEN
        RETURN -2;
    END IF;

    DELETE FROM tbl_sso_connection_domains
    WHERE  connection_id = p_connectionId AND client_id = p_clientId;

    IF coalesce(array_length(p_domains, 1), 0) > 0 THEN
        INSERT INTO tbl_sso_connection_domains (domain, connection_id, client_id)
        SELECT DISTINCT lower(d), p_connectionId, p_clientId FROM unnest(p_domains) AS d;
        GET DIAGNOSTICS v_inserted = ROW_COUNT;
    END IF;

    RETURN v_inserted;
END;
$$;
