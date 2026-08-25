/****** Object: Stored Procedure [stp_CreateResetToken] ******/
-- Mints a reset token, stored as its hash only. The caller deletes any
-- outstanding token first so exactly one link is ever live — otherwise
-- re-issuing would leave an earlier, possibly leaked link redeemable.
--
-- Implemented as a FUNCTION, not a PROCEDURE: the caller needs the result,
-- and PostgreSQL procedures cannot return a result set.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_CreateResetToken(p_userId TEXT, p_clientId TEXT, p_tokenHash TEXT, p_expiresAt TIMESTAMPTZ, p_createdBy TEXT)
RETURNS SETOF tbl_password_reset_tokens
LANGUAGE sql
VOLATILE
AS $$
    INSERT INTO tbl_password_reset_tokens (user_id, client_id, token_hash, expires_at, created_by)
    VALUES (p_userId, p_clientId, p_tokenHash, p_expiresAt, p_createdBy)
    RETURNING *;
$$;
