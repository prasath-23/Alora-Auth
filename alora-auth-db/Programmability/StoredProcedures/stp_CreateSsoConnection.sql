/****** Object: Stored Procedure [stp_CreateSsoConnection] ******/
-- Registers a tenant's OIDC identity provider. The id is chosen by the
-- caller because the secret is encrypted with the id as associated data
-- before it reaches the database.
--
-- Implemented as a FUNCTION, not a PROCEDURE: the caller needs the result,
-- and PostgreSQL procedures cannot return a result set.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_CreateSsoConnection(p_connectionId TEXT, p_clientId TEXT, p_name TEXT, p_issuer TEXT, p_oidcClientId TEXT, p_secretCiphertext BYTEA, p_secretKeyId TEXT, p_scopes TEXT, p_trustUnverifiedEmail BOOLEAN, p_isActive BOOLEAN)
RETURNS SETOF tbl_sso_connections
LANGUAGE sql
VOLATILE
AS $$
    INSERT INTO tbl_sso_connections (id, client_id, name, issuer, oidc_client_id,
                                     client_secret_ciphertext, secret_key_id, scopes,
                                     trust_unverified_email, is_active)
    VALUES (p_connectionId, p_clientId, p_name, p_issuer, p_oidcClientId,
            p_secretCiphertext, p_secretKeyId, p_scopes, p_trustUnverifiedEmail, p_isActive)
    RETURNING *;
$$;
