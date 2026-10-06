/****** Object: Table-valued Function [udf_ListInvitationGroups] ******/
-- The groups an invitation adds its user to, applied on acceptance.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_ListInvitationGroups(p_invitationId TEXT)
RETURNS SETOF vw_InvitationGroup
LANGUAGE sql
STABLE
AS $$
    SELECT * FROM vw_InvitationGroup v
    WHERE  v.invitation_id = p_invitationId
    ORDER  BY v.group_name;
$$;
