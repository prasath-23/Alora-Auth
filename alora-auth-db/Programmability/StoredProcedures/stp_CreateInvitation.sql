/****** Object: Stored Procedure [stp_CreateInvitation] ******/
-- Issues an invitation, from a tenant Admin or from an Owner. Only the
-- token's SHA-256 is stored; the raw value exists solely in the email that
-- was sent, so a database leak yields nothing redeemable. The address is
-- lower-cased for index alignment. An invitation to this address still
-- marked PENDING but past its expiry is marked EXPIRED first -- the sweep
-- may not have reached it yet -- so that
-- UQ_tbl_invitations_client_email_pending refuses only a live one: a second
-- live invitation to the address raises 23505, which the caller maps to 409.
--
-- Implemented as a FUNCTION, not a PROCEDURE: the caller needs the result,
-- and PostgreSQL procedures cannot return a result set.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_CreateInvitation(p_email TEXT, p_clientId TEXT, p_invitedByUserId TEXT, p_invitedByOwnerId TEXT, p_tokenHash TEXT, p_expiresAt TIMESTAMPTZ)
RETURNS SETOF tbl_invitations
LANGUAGE sql
VOLATILE
AS $$
    UPDATE tbl_invitations
    SET    status = 'EXPIRED'
    WHERE  client_id    = p_clientId
      AND  lower(email) = lower(p_email)
      AND  status       = 'PENDING'
      AND  expires_at  <= now();

    INSERT INTO tbl_invitations (email, client_id, invited_by_user_id, invited_by_owner_id,
                                 token_hash, expires_at)
    VALUES (lower(p_email), p_clientId, p_invitedByUserId, p_invitedByOwnerId,
            p_tokenHash, p_expiresAt)
    RETURNING *;
$$;
