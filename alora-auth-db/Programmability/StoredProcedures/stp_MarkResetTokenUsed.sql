/****** Object: Stored Procedure [stp_MarkResetTokenUsed] ******/
-- Burns a reset token after the password has been changed, inside the same
-- transaction as that change so the two can never diverge.
--
-- Implemented as a PROCEDURE: nothing needs to be returned, so the caller
-- invokes it with CALL.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE PROCEDURE stp_MarkResetTokenUsed(p_tokenId TEXT)
LANGUAGE sql
AS $$
    UPDATE tbl_password_reset_tokens
    SET    used_at = now()
    WHERE  id = p_tokenId;
$$;
