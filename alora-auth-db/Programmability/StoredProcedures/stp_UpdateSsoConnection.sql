/****** Object: Stored Procedure [stp_UpdateSsoConnection] ******/
-- Updates a connection, tenant-scoped. A NULL secret keeps the stored one,
-- so editing other fields never requires re-entering it.
--
-- Implemented as a FUNCTION, not a PROCEDURE: the caller needs the result,
-- and PostgreSQL procedures cannot return a result set.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_UpdateSsoConnection(p_connectionId TEXT, p_clientId TEXT, p_name TEXT, p_issuer TEXT, p_oidcClientId TEXT, p_secretCiphertext BYTEA, p_secretKeyId TEXT, p_scopes TEXT, p_trustUnverifiedEmail BOOLEAN, p_isActive BOOLEAN)
RETURNS SETOF tbl_sso_connections
LANGUAGE sql
VOLATILE
AS $$
    UPDATE tbl_sso_connections
    SET    name                     = p_name,
           issuer                   = p_issuer,
           oidc_client_id           = p_oidcClientId,
           client_secret_ciphertext = COALESCE(p_secretCiphertext, client_secret_ciphertext),
           secret_key_id            = COALESCE(p_secretKeyId, secret_key_id),
           scopes                   = p_scopes,
           trust_unverified_email   = p_trustUnverifiedEmail,
           is_active                = p_isActive,
           updated_at               = now()
    WHERE  id        = p_connectionId
      AND  client_id = p_clientId
    RETURNING *;
$$;
