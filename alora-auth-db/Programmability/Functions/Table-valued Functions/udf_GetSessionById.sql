/****** Object: Table-valued Function [udf_GetSessionById] ******/
-- Internal lookup used while walking the rotation chain. Deliberately
-- ignores revocation: the caller needs to inspect a revoked successor to
-- tell a benign concurrent refresh from a genuine replay.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_GetSessionById(p_sessionId TEXT)
RETURNS SETOF tbl_user_sessions
LANGUAGE sql
STABLE
AS $$
    SELECT * FROM tbl_user_sessions s WHERE s.id = p_sessionId;
$$;
