/****** Object: Stored Procedure [stp_DeleteLinkedIdentity] ******/
-- Unlinks an external identity, tenant-scoped.
--
-- Implemented as a FUNCTION, not a PROCEDURE: the caller needs the result,
-- and PostgreSQL procedures cannot return a result set.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_DeleteLinkedIdentity(p_userId TEXT, p_clientId TEXT, p_provider "IdpProvider", p_connectionId TEXT)
RETURNS INTEGER
LANGUAGE sql
VOLATILE
AS $$
    WITH del AS (
        DELETE FROM tbl_linked_identities
        WHERE  user_id   = p_userId
          AND  client_id = p_clientId
          AND  provider  = p_provider
          AND  connection_id IS NOT DISTINCT FROM p_connectionId
        RETURNING 1
    )
    SELECT count(*)::int FROM del;
$$;
