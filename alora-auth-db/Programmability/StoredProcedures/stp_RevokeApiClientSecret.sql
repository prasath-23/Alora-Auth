/****** Object: Stored Procedure [stp_RevokeApiClientSecret] ******/
-- Revokes one secret by stamping revoked_at, tenant-scoped and guarded on
-- not yet revoked, so an unknown, another tenant's or an already revoked
-- secret reports 0.
--
-- Implemented as a FUNCTION, not a PROCEDURE: the caller needs the result,
-- and PostgreSQL procedures cannot return a result set.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_RevokeApiClientSecret(p_secretId TEXT, p_apiClientId TEXT, p_clientId TEXT)
RETURNS INTEGER
LANGUAGE sql
VOLATILE
AS $$
    WITH upd AS (
        UPDATE tbl_api_client_secrets
        SET    revoked_at = now()
        WHERE  id            = p_secretId
          AND  api_client_id = p_apiClientId
          AND  client_id     = p_clientId
          AND  revoked_at IS NULL
        RETURNING 1
    )
    SELECT count(*)::int FROM upd;
$$;
