/****** Object: Stored Procedure [stp_DeleteApiClient] ******/
-- Deletes an API client, and with it its scopes, products and secrets,
-- tenant-scoped. The audit trail keeps what it was: its rows name the client
-- in their metadata, not by a key.
--
-- Implemented as a FUNCTION, not a PROCEDURE: the caller needs the result,
-- and PostgreSQL procedures cannot return a result set.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_DeleteApiClient(p_apiClientId TEXT, p_clientId TEXT)
RETURNS INTEGER
LANGUAGE sql
VOLATILE
AS $$
    WITH del AS (
        DELETE FROM tbl_api_clients
        WHERE  id        = p_apiClientId
          AND  client_id = p_clientId
        RETURNING 1
    )
    SELECT count(*)::int FROM del;
$$;
