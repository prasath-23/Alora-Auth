/****** Object: Stored Procedure [stp_CreateApiClientSecret] ******/
-- Adds a secret to an API client. Only its SHA-256 and a short prefix -- enough
-- to tell two secrets apart on screen, never enough to use -- are stored; the
-- plaintext is shown once, by the caller, and never again.
--
-- At most two secrets are live at a time, so a client rotates without downtime:
-- make a second, deploy it, revoke the first. The API client's row is locked,
-- so two concurrent requests cannot both add a second secret.
--
-- Returns ZERO rows when the API client is not in this tenant, or already has
-- two live secrets; the caller has checked the first, so it reports the second.
-- The row returned is the secret's projection, never its hash.
--
-- Implemented as a FUNCTION: the caller needs the new secret's row.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_CreateApiClientSecret(
    p_apiClientId      TEXT,
    p_clientId         TEXT,
    p_secretHash       TEXT,
    p_prefix           TEXT,
    p_expiresAt        TIMESTAMPTZ,
    p_createdByUserId  TEXT,
    p_createdByOwnerId TEXT
)
RETURNS SETOF vw_ApiClientSecret
LANGUAGE plpgsql
VOLATILE
AS $$
DECLARE
    v_id TEXT;
BEGIN
    PERFORM 1
    FROM   tbl_api_clients a
    WHERE  a.id = p_apiClientId AND a.client_id = p_clientId
    FOR    UPDATE;

    IF NOT FOUND THEN
        RETURN;
    END IF;

    IF (SELECT count(*)
        FROM   tbl_api_client_secrets x
        WHERE  x.api_client_id = p_apiClientId
          AND  x.client_id     = p_clientId
          AND  x.revoked_at IS NULL
          AND  (x.expires_at IS NULL OR x.expires_at > now())) >= 2 THEN
        RETURN;
    END IF;

    INSERT INTO tbl_api_client_secrets (api_client_id, client_id, secret_hash, prefix, expires_at,
                                        created_by_user_id, created_by_owner_id)
    VALUES (p_apiClientId, p_clientId, p_secretHash, p_prefix, p_expiresAt,
            p_createdByUserId, p_createdByOwnerId)
    RETURNING id INTO v_id;

    RETURN QUERY SELECT * FROM vw_ApiClientSecret v WHERE v.id = v_id;
END;
$$;
