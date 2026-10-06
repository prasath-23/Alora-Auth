/****** Object: Stored Procedure [stp_ManagerAddGroupMember] ******/
-- A group's manager adds a member. The API has already checked that the caller
-- manages the group; this checks again at the moment of the change, so a
-- manager dismissed after their request began is still refused:
--
--   * the group row is share-locked, which waits for a dismissal holding it
--     (stp_RemoveGroupManager locks it FOR UPDATE);
--   * then, in a NEW statement -- so a dismissal that has just committed is
--     seen -- the caller must still manage the group (-1 otherwise, and when
--     the group is not in this tenant).
--
-- Also refused: a system group (-2; it never has managers, so this is defence
-- in depth); one of the group's own managers as the member, the caller
-- included (-3: managers do not decide their own or each other's membership);
-- and anyone who is not a live user of the tenant (-4).
--
-- Returns 1 when added, 0 when already a member. The member's
-- permissions_version and admin_version are bumped in this same transaction.
--
-- Implemented as a FUNCTION: the caller needs the outcome.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_ManagerAddGroupMember(
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
    v_system TEXT;
    v_added  INTEGER;
    v_pid    TEXT;
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
        RETURN -3;  -- -3 = the member would be one of the group's managers
    END IF;
    PERFORM 1 FROM tbl_users u
    WHERE  u.id = p_userId AND u.client_id = p_clientId AND u.deleted_at IS NULL;
    IF NOT FOUND THEN
        RETURN -4;  -- -4 = no such live user in this tenant
    END IF;

    INSERT INTO tbl_user_groups (user_id, group_id, client_id, assigned_by)
    VALUES (p_userId, p_groupId, p_clientId, p_managerId)
    ON CONFLICT (user_id, group_id) DO NOTHING;
    GET DIAGNOSTICS v_added = ROW_COUNT;

    IF v_added > 0 THEN
        UPDATE tbl_users
        SET    permissions_version = permissions_version + 1,
               admin_version       = admin_version + 1
        WHERE  id = p_userId AND client_id = p_clientId;

        -- Joining the group grants its products; hold each one's seat_limit.
        FOR v_pid IN
            SELECT product_id FROM tbl_group_product_grants
            WHERE  group_id = p_groupId AND client_id = p_clientId
            ORDER  BY product_id
        LOOP
            PERFORM stp_AssertProductSeat(p_clientId, v_pid);
        END LOOP;
    END IF;
    RETURN v_added;
END;
$$;
