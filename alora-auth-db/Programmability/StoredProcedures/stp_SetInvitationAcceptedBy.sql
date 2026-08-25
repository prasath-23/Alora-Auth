/****** Object: Stored Procedure [stp_SetInvitationAcceptedBy] ******/
-- Links a newly created account back to the invitation it came from. The id
-- is a trusted server value returned by the claim, never client input.
--
-- Implemented as a PROCEDURE: nothing needs to be returned, so the caller
-- invokes it with CALL.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE PROCEDURE stp_SetInvitationAcceptedBy(p_invitationId TEXT, p_acceptedByUserId TEXT)
LANGUAGE sql
AS $$
    UPDATE tbl_invitations
    SET    accepted_by_user_id = p_acceptedByUserId,
           updated_at          = now()
    WHERE  id = p_invitationId;
$$;
