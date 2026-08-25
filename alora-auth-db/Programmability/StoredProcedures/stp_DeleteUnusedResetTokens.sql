/****** Object: Stored Procedure [stp_DeleteUnusedResetTokens] ******/
-- Invalidates every unspent reset token for a user. Used tokens are kept as
-- an audit record of when a reset actually happened.
--
-- Implemented as a PROCEDURE: nothing needs to be returned, so the caller
-- invokes it with CALL.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE PROCEDURE stp_DeleteUnusedResetTokens(p_userId TEXT)
LANGUAGE sql
AS $$
    DELETE FROM tbl_password_reset_tokens
    WHERE  user_id  = p_userId
      AND  used_at IS NULL;
$$;
