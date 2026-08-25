/****** Object: Table-valued Function [udf_ListInvitationProducts] ******/
-- The products an invitation confers, applied on acceptance.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_ListInvitationProducts(p_invitationId TEXT)
RETURNS SETOF vw_InvitationProductRole
LANGUAGE sql
STABLE
AS $$
    SELECT * FROM vw_InvitationProductRole v
    WHERE  v.invitation_id = p_invitationId
    ORDER  BY v.product_name;
$$;
