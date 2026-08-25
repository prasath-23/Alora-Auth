/****** Object: Stored Procedure [stp_CreateInvitation] ******/
-- Issues an invitation. Only the token's SHA-256 is stored; the raw value
-- exists solely in the email that was sent, so a database leak yields
-- nothing redeemable. The address is lower-cased for index alignment.
--
-- Implemented as a FUNCTION, not a PROCEDURE: the caller needs the result,
-- and PostgreSQL procedures cannot return a result set.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_CreateInvitation(p_email TEXT, p_clientId TEXT, p_invitedByUserId TEXT, p_tokenHash TEXT, p_expiresAt TIMESTAMPTZ)
RETURNS SETOF tbl_invitations
LANGUAGE sql
VOLATILE
AS $$
    INSERT INTO tbl_invitations (email, client_id, invited_by_user_id, token_hash, expires_at)
    VALUES (lower(p_email), p_clientId, p_invitedByUserId, p_tokenHash, p_expiresAt)
    RETURNING *;
$$;
