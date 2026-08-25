/****** Object: Table-valued Function [udf_ListInvitations] ******/
-- The admin invitation list, newest first and capped.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_ListInvitations(p_clientId TEXT)
RETURNS SETOF vw_InvitationListItem
LANGUAGE sql
STABLE
AS $$
    SELECT * FROM vw_InvitationListItem v
    WHERE  v.client_id = p_clientId
    ORDER  BY v.created_at DESC
    LIMIT  100;
$$;
