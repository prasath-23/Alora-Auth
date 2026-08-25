/****** Object: Stored Procedure [stp_CreateSuccessorSession] ******/
-- Appends the next generation to an existing family. The family id is
-- inherited, never regenerated — that is what keeps a stolen token traceable
-- to every other token derived from the same login. prev_token_hash is what
-- makes the grace-window race detectable. A collision on (family_id,
-- generation) means a concurrent rotation won, and the unique index turns
-- that into 23505 rather than a forked family.
--
-- Implemented as a FUNCTION, not a PROCEDURE: the caller needs the result,
-- and PostgreSQL procedures cannot return a result set.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_CreateSuccessorSession(p_userId TEXT, p_clientId TEXT, p_sessionUuid TEXT, p_familyId TEXT, p_generation INTEGER, p_refreshTokenHash TEXT, p_prevTokenHash TEXT, p_expiresAt TIMESTAMPTZ, p_ipAddress TEXT, p_deviceLabel TEXT, p_userAgent TEXT)
RETURNS SETOF tbl_user_sessions
LANGUAGE sql
VOLATILE
AS $$
    INSERT INTO tbl_user_sessions (user_id, client_id, session_uuid, family_id, generation,
                                   refresh_token_hash, prev_token_hash, expires_at,
                                   ip_address, device_label, user_agent)
    VALUES (p_userId, p_clientId, p_sessionUuid, p_familyId, p_generation,
            p_refreshTokenHash, p_prevTokenHash, p_expiresAt,
            p_ipAddress, p_deviceLabel, p_userAgent)
    RETURNING *;
$$;
