/****** Object: View [vw_UserGroupMembership] ******/
-- A user's group memberships, with the group's name resolved. Joined on the
-- group's OWN client_id so a membership can never surface a group from
-- another tenant, and soft-deleted users are excluded so they do not appear
-- as members.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE VIEW vw_UserGroupMembership AS
SELECT ug.user_id,
       ug.client_id,
       ug.group_id,
       g.name        AS group_name,
       ug.assigned_at
FROM   tbl_user_groups ug
JOIN   tbl_groups g ON g.id = ug.group_id
                   AND g.client_id = ug.client_id
JOIN   tbl_users  u ON u.id = ug.user_id
                   AND u.deleted_at IS NULL;
