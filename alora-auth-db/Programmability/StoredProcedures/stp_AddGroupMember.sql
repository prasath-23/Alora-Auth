/****** Object: Stored Procedure [stp_AddGroupMember] ******/
-- Adds a member. A duplicate raises 23505 on the composite primary key, and
-- the composite tenant foreign key independently refuses a user from another
-- organisation even if the caller's checks were bypassed.
--
-- Implemented as a PROCEDURE: nothing needs to be returned, so the caller
-- invokes it with CALL.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE PROCEDURE stp_AddGroupMember(p_userId TEXT, p_groupId TEXT, p_clientId TEXT, p_assignedBy TEXT)
LANGUAGE sql
AS $$
    INSERT INTO tbl_user_groups (user_id, group_id, client_id, assigned_by)
    VALUES (p_userId, p_groupId, p_clientId, p_assignedBy);
$$;
