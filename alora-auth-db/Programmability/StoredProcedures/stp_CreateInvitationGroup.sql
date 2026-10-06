/****** Object: Stored Procedure [stp_CreateInvitationGroup] ******/
-- Attaches one group to an invitation, inside the same transaction as the
-- invitation itself, so a committed invitation always carries what it
-- offered.
--
-- Implemented as a PROCEDURE: nothing needs to be returned, so the caller
-- invokes it with CALL.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE PROCEDURE stp_CreateInvitationGroup(p_invitationId TEXT, p_clientId TEXT, p_groupId TEXT)
LANGUAGE sql
AS $$
    INSERT INTO tbl_invitation_groups (invitation_id, client_id, group_id)
    VALUES (p_invitationId, p_clientId, p_groupId);
$$;
