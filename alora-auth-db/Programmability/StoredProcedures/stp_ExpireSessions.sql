/****** Object: Stored Procedure [stp_ExpireSessions] ******/
-- Scheduled sweep for timed-out sessions. Batched so the transaction stays
-- short and never holds locks against live rotation traffic. Purely hygiene:
-- every read path already filters on expires_at, so a late sweep is not a
-- security gap.
--
-- Implemented as a PROCEDURE: nothing needs to be returned, so the caller
-- invokes it with CALL.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE PROCEDURE stp_ExpireSessions(p_batchSize INTEGER DEFAULT 500)
LANGUAGE sql
AS $$
    UPDATE tbl_user_sessions
    SET    revoked_at     = now(),
           revoked_reason = 'EXPIRED'
    WHERE  id IN (
        SELECT s.id
        FROM   tbl_user_sessions s
        WHERE  s.expires_at  < now()
          AND  s.revoked_at IS NULL
        LIMIT  p_batchSize
    );
$$;
