/****** Object: Stored Procedure [stp_DeleteGroup] ******/
-- Deletes a group; its scopes, grants, memberships and managers cascade.
-- Tenant-scoped, and never a system group. Everyone it touched is bumped
-- ONCE, in the same statement: a former member's permissions_version and
-- admin_version (what the group granted stops applying at their next token,
-- not whenever the old one expires), a former manager's admin_version (they
-- no longer run it). Members and managers are merged first, so someone who
-- was both gets one bump of each version, not two -- and never loses one to
-- a second UPDATE of the same row. (All the CTEs share one snapshot, so they
-- still see the rows the delete cascades away.)
--
-- Implemented as a FUNCTION, not a PROCEDURE: the caller needs the result,
-- and PostgreSQL procedures cannot return a result set.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_DeleteGroup(p_groupId TEXT, p_clientId TEXT)
RETURNS INTEGER
LANGUAGE sql
VOLATILE
AS $$
    WITH touched AS (
        SELECT t.user_id, t.client_id, bool_or(t.is_member) AS is_member
        FROM  (SELECT ug.user_id, ug.client_id, true AS is_member
               FROM   tbl_user_groups ug
               WHERE  ug.group_id  = p_groupId
                 AND  ug.client_id = p_clientId
               UNION ALL
               SELECT gm.user_id, gm.client_id, false
               FROM   tbl_group_managers gm
               WHERE  gm.group_id  = p_groupId
                 AND  gm.client_id = p_clientId) t
        GROUP  BY t.user_id, t.client_id
    ), del AS (
        DELETE FROM tbl_groups
        WHERE  id          = p_groupId
          AND  client_id   = p_clientId
          AND  system_key IS NULL
        RETURNING 1
    ), bump AS (
        UPDATE tbl_users u
        SET    permissions_version = u.permissions_version
                                     + CASE WHEN t.is_member THEN 1 ELSE 0 END,
               admin_version       = u.admin_version + 1
        FROM   touched t
        WHERE  u.id        = t.user_id
          AND  u.client_id = t.client_id
          AND  EXISTS (SELECT 1 FROM del)
        RETURNING 1
    )
    SELECT count(*)::int FROM del;
$$;
