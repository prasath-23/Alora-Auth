/****** Object: Stored Procedure [stp_RemoveGroupManager] ******/
-- Dismisses a group's manager, scoped by group, user and tenant together, so a
-- foreign id removes nothing. Returns 1 when dismissed, 0 when they did not
-- manage it, -1 when the group is not in this tenant.
--
-- The group row is locked FOR UPDATE first. A manager's membership change
-- (stp_ManagerAddGroupMember, stp_ManagerRemoveGroupMember) share-locks the same
-- row and only then checks that its caller still manages the group, so the two
-- serialise: a manager dismissed a moment ago cannot slip one more change in.
--
-- A dismissal bumps the former manager's admin_version in this same
-- transaction.
--
-- Implemented as a FUNCTION: the caller needs the outcome.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_RemoveGroupManager(
    p_groupId  TEXT,
    p_clientId TEXT,
    p_userId   TEXT
)
RETURNS INTEGER
LANGUAGE plpgsql
VOLATILE
AS $$
DECLARE
    v_removed INTEGER;
BEGIN
    PERFORM 1 FROM tbl_groups g
    WHERE  g.id = p_groupId AND g.client_id = p_clientId
    FOR    UPDATE;
    IF NOT FOUND THEN
        RETURN -1;  -- -1 = no such group in this tenant
    END IF;

    DELETE FROM tbl_group_managers
    WHERE  group_id  = p_groupId
      AND  client_id = p_clientId
      AND  user_id   = p_userId;
    GET DIAGNOSTICS v_removed = ROW_COUNT;

    IF v_removed > 0 THEN
        UPDATE tbl_users
        SET    admin_version = admin_version + 1
        WHERE  id = p_userId AND client_id = p_clientId;
    END IF;
    RETURN v_removed;
END;
$$;
