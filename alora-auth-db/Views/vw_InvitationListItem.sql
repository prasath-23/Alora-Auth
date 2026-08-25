/****** Object: View [vw_InvitationListItem] ******/
-- The admin invitation-list row. token_hash is never projected: it is a
-- credential at rest and useless to any caller.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE VIEW vw_InvitationListItem AS
SELECT i.id,
       i.client_id,
       i.email,
       i.status,
       i.expires_at,
       i.created_at
FROM   tbl_invitations i;
