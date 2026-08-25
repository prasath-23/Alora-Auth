/****** Object: Stored Procedure [stp_MarkSessionReplaced] ******/
-- Retires a rotated session. revoked_reason is left NULL on purpose: a
-- normal rotation is not a revocation event, and conflating the two would
-- make a genuine security revocation indistinguishable from routine refresh
-- traffic.
--
-- Implemented as a PROCEDURE: nothing needs to be returned, so the caller
-- invokes it with CALL.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE PROCEDURE stp_MarkSessionReplaced(p_sessionId TEXT, p_replacedById TEXT)
LANGUAGE sql
AS $$
    UPDATE tbl_user_sessions
    SET    revoked_at     = now(),
           replaced_by_id = p_replacedById
    WHERE  id = p_sessionId;
$$;
