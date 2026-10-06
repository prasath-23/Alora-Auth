/****** Object: Stored Procedure [stp_RemoveGroupMember] ******/
-- Removes a member, scoped by user, group and tenant together so a foreign group
-- id removes nothing.
--
-- Refuses (-2) to remove the last ACTIVE member of a tenant's ADMINS group: that
-- would leave the organisation with nobody able to administer it. The group row
-- is locked first, so two concurrent removals of the last two admins serialise
-- and the second sees the first.
--
-- Implemented as a FUNCTION: the caller needs the outcome.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_RemoveGroupMember(
    p_userId   TEXT,
    p_groupId  TEXT,
    p_clientId TEXT
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
    FOR    UPDATE;

    IF v_system = 'ADMINS'
       AND EXISTS (SELECT 1 FROM tbl_user_groups
                   WHERE  group_id = p_groupId AND client_id = p_clientId AND user_id = p_userId)
       AND NOT EXISTS (
            SELECT 1
            FROM   tbl_user_groups ug
            JOIN   tbl_users u ON u.id = ug.user_id AND u.client_id = ug.client_id
            WHERE  ug.group_id   = p_groupId
              AND  ug.client_id  = p_clientId
              AND  ug.user_id   <> p_userId
              AND  u.deleted_at IS NULL
              AND  u.is_active   = true) THEN
        RETURN -2;  -- -2 = this is the last active Admin
    END IF;

    DELETE FROM tbl_user_groups
    WHERE  user_id   = p_userId
      AND  group_id  = p_groupId
      AND  client_id = p_clientId;
    GET DIAGNOSTICS v_removed = ROW_COUNT;

    -- Same transaction as the removal: what the group granted stops applying at
    -- the member's next token.
    IF v_removed > 0 THEN
        UPDATE tbl_users
        SET    permissions_version = permissions_version + 1,
               admin_version       = admin_version + 1
        WHERE  id = p_userId AND client_id = p_clientId;
    END IF;
    RETURN v_removed;
END;
$$;
