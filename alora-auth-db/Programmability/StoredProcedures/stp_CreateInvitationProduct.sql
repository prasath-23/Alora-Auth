/****** Object: Stored Procedure [stp_CreateInvitationProduct] ******/
-- Attaches one product grant to an invitation. Called once per grant inside
-- the same transaction as the invitation itself, so a committed invitation
-- always carries the access it promised.
--
-- Implemented as a PROCEDURE: nothing needs to be returned, so the caller
-- invokes it with CALL.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE PROCEDURE stp_CreateInvitationProduct(p_invitationId TEXT, p_productId TEXT, p_roleName TEXT)
LANGUAGE sql
AS $$
    INSERT INTO tbl_invitation_products (invitation_id, product_id, role_name)
    VALUES (p_invitationId, p_productId, p_roleName);
$$;
