/****** Object: Stored Procedure [stp_CreateCentralFamily] ******/
-- Opens a CENTRAL login at App Central: the family row, which carries how the
-- user authenticated and the absolute cap every refresh is bounded by, and its
-- first refresh-token generation. Only the token's hash is stored.
--
-- Implemented as a FUNCTION: the caller needs the session row (and through it
-- the family id).
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_CreateCentralFamily(
    p_userId            TEXT,
    p_clientId          TEXT,
    p_authMethod        "IdpProvider",
    p_authConnectionId  TEXT,
    p_absoluteExpiresAt TIMESTAMPTZ,
    p_sessionUuid       TEXT,
    p_refreshTokenHash  TEXT,
    p_expiresAt         TIMESTAMPTZ,
    p_ipAddress         TEXT,
    p_deviceLabel       TEXT,
    p_userAgent         TEXT
)
RETURNS SETOF tbl_user_sessions
LANGUAGE plpgsql
VOLATILE
AS $$
DECLARE
    v_familyId TEXT;
BEGIN
    INSERT INTO tbl_session_families (user_id, client_id, kind, auth_method,
                                      auth_connection_id, absolute_expires_at)
    VALUES (p_userId, p_clientId, 'CENTRAL', p_authMethod,
            p_authConnectionId, p_absoluteExpiresAt)
    RETURNING id INTO v_familyId;

    RETURN QUERY
    INSERT INTO tbl_user_sessions (user_id, client_id, session_uuid, family_id,
                                   refresh_token_hash, expires_at,
                                   ip_address, device_label, user_agent)
    VALUES (p_userId, p_clientId, p_sessionUuid, v_familyId,
            p_refreshTokenHash, LEAST(p_expiresAt, p_absoluteExpiresAt),
            p_ipAddress, p_deviceLabel, p_userAgent)
    RETURNING *;
END;
$$;
