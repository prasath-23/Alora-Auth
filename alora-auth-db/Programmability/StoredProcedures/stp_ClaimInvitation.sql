/****** Object: Stored Procedure [stp_ClaimInvitation] ******/
-- Redeems an invitation in ONE atomic statement, guarded on PENDING and not
-- expired, so two concurrent acceptances cannot both create an account.
-- p_acceptedByUserId is NULL on the registration path, where the user does
-- not exist yet and is linked afterwards by stp_SetInvitationAcceptedBy.
--
-- Implemented as a FUNCTION, not a PROCEDURE: the caller needs the result,
-- and PostgreSQL procedures cannot return a result set.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_ClaimInvitation(p_tokenHash TEXT, p_acceptedByUserId TEXT DEFAULT NULL)
RETURNS SETOF tbl_invitations
LANGUAGE sql
VOLATILE
AS $$
    UPDATE tbl_invitations
    SET    status              = 'ACCEPTED',
           accepted_at         = now(),
           accepted_by_user_id = COALESCE(p_acceptedByUserId, accepted_by_user_id),
           updated_at          = now()
    WHERE  token_hash = p_tokenHash
      AND  status     = 'PENDING'
      AND  expires_at > now()
    RETURNING *;
$$;
