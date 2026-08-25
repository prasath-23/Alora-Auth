/****** Object: Stored Procedure [stp_CreateSession] ******/
-- Opens a NEW token family at login. Generation defaults to 0 and
-- prev_token_hash stays NULL, marking this as the root of the chain. Only
-- the hash of the token is stored.
--
-- Implemented as a FUNCTION, not a PROCEDURE: the caller needs the result,
-- and PostgreSQL procedures cannot return a result set.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_CreateSession(p_userId TEXT, p_clientId TEXT, p_sessionUuid TEXT, p_familyId TEXT, p_refreshTokenHash TEXT, p_expiresAt TIMESTAMPTZ, p_ipAddress TEXT, p_deviceLabel TEXT, p_userAgent TEXT)
RETURNS SETOF tbl_user_sessions
LANGUAGE sql
VOLATILE
AS $$
    INSERT INTO tbl_user_sessions (user_id, client_id, session_uuid, family_id,
                                   refresh_token_hash, expires_at,
                                   ip_address, device_label, user_agent)
    VALUES (p_userId, p_clientId, p_sessionUuid, p_familyId,
            p_refreshTokenHash, p_expiresAt,
            p_ipAddress, p_deviceLabel, p_userAgent)
    RETURNING *;
$$;
