/****** Object: View [vw_InvitationGroup] ******/
-- The groups an invitation adds its user to, with the group's name resolved.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE VIEW vw_InvitationGroup AS
SELECT ig.invitation_id,
       ig.client_id,
       ig.group_id,
       g.name AS group_name
FROM   tbl_invitation_groups ig
JOIN   tbl_groups g ON g.id = ig.group_id
                   AND g.client_id = ig.client_id;
