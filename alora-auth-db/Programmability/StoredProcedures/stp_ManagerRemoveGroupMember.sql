/****** Object: Stored Procedure [stp_ManagerRemoveGroupMember] ******/
-- A group's manager removes a member, with the same checks at the moment of the
-- change as stp_ManagerAddGroupMember: the caller must still manage the group
-- (-1), never a system group (-2), never one of the group's managers, the
-- caller included (-3). Returns 1 when removed, 0 when they were not a member;
-- the member's versions are bumped in this same transaction.
--
-- Implemented as a FUNCTION: the caller needs the outcome.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_ManagerRemoveGroupMember(
    p_managerId TEXT,
    p_userId    TEXT,
    p_groupId   TEXT,
    p_clientId  TEXT
)
RETURNS INTEGER
LANGUAGE plpgsql
VOLATILE
AS $$
DECLARE
    v_system  TEXT;
    v_removed INTEGER;
BEGIN
    SELECT g.system_key INTO v_system
    FROM   tbl_groups g
    WHERE  g.id = p_groupId AND g.client_id = p_clientId
    FOR    SHARE;
    IF NOT FOUND THEN
        RETURN -1;
    END IF;
    PERFORM 1 FROM tbl_group_managers gm
    WHERE  gm.group_id = p_groupId AND gm.client_id = p_clientId AND gm.user_id = p_managerId;
    IF NOT FOUND THEN
        RETURN -1;  -- -1 = the caller does not manage this group
    END IF;
    IF v_system IS NOT NULL THEN
        RETURN -2;  -- -2 = a system group
    END IF;
    PERFORM 1 FROM tbl_group_managers gm
    WHERE  gm.group_id = p_groupId AND gm.client_id = p_clientId AND gm.user_id = p_userId;
    IF FOUND THEN
        RETURN -3;  -- -3 = the member is one of the group's managers
    END IF;

    DELETE FROM tbl_user_groups
    WHERE  user_id   = p_userId
      AND  group_id  = p_groupId
      AND  client_id = p_clientId;
    GET DIAGNOSTICS v_removed = ROW_COUNT;

    IF v_removed > 0 THEN
        UPDATE tbl_users
        SET    permissions_version = permissions_version + 1,
               admin_version       = admin_version + 1
        WHERE  id = p_userId AND client_id = p_clientId;
    END IF;
    RETURN v_removed;
END;
$$;
