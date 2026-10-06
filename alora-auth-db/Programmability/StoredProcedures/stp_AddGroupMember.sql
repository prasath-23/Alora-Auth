/****** Object: Stored Procedure [stp_AddGroupMember] ******/
-- Adds a member and bumps their permissions_version and admin_version in the same
-- statement, so the membership and the signal that their tokens are stale cannot
-- come apart. A duplicate raises 23505 on the composite primary key, and the
-- composite tenant foreign keys independently refuse a user or group from another
-- organisation even if the caller's checks were bypassed.
--
-- SEAT LIMIT: joining a group grants the member every product the group confers,
-- so after the insert each such product's seat_limit is enforced
-- (stp_AssertProductSeat), in product-id order so concurrent adds take the
-- subscription locks in a consistent order. Over a limit rolls the join back as 409.
--
-- Implemented as a PROCEDURE: nothing is returned, so the caller invokes it with
-- CALL. plpgsql (not plain SQL) because of the seat guard.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE PROCEDURE stp_AddGroupMember(p_userId TEXT, p_groupId TEXT, p_clientId TEXT, p_assignedBy TEXT)
LANGUAGE plpgsql
AS $$
DECLARE
    v_pid TEXT;
BEGIN
    WITH ins AS (
        INSERT INTO tbl_user_groups (user_id, group_id, client_id, assigned_by)
        VALUES (p_userId, p_groupId, p_clientId, p_assignedBy)
        RETURNING user_id, client_id
    )
    UPDATE tbl_users u
    SET    permissions_version = u.permissions_version + 1,
           admin_version       = u.admin_version + 1
    FROM   ins
    WHERE  u.id = ins.user_id AND u.client_id = ins.client_id;

    FOR v_pid IN
        SELECT product_id FROM tbl_group_product_grants
        WHERE  group_id = p_groupId AND client_id = p_clientId
        ORDER  BY product_id
    LOOP
        PERFORM stp_AssertProductSeat(p_clientId, v_pid);
    END LOOP;
END;
$$;
