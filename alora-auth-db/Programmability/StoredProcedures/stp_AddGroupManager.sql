/****** Object: Stored Procedure [stp_AddGroupManager] ******/
-- Appoints a manager of a group: someone who may add and remove its members and
-- nothing else. The group is looked up by (id, tenant): -1 when it is not in
-- this tenant. A system group never has managers (-2): whoever could change the
-- Admins group's members could make anyone an Admin. The appointee must be a
-- live user of the tenant (-3); the composite keys refuse another tenant's user
-- anyway, and a CHECK refuses anyone appointing themselves.
--
-- Returns 1 when appointed, 0 when they already manage it. An appointment bumps
-- the appointee's admin_version in this same transaction: their login token
-- describes what they may do in App Central, and it is now out of date.
--
-- The group row is share-locked, so it cannot be deleted mid-appointment.
--
-- Implemented as a FUNCTION: the caller needs the outcome.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_AddGroupManager(
    p_groupId   TEXT,
    p_clientId  TEXT,
    p_userId    TEXT,
    p_byUserId  TEXT,
    p_byOwnerId TEXT
)
RETURNS INTEGER
LANGUAGE plpgsql
VOLATILE
AS $$
DECLARE
    v_system TEXT;
    v_added  INTEGER;
BEGIN
    SELECT g.system_key INTO v_system
    FROM   tbl_groups g
    WHERE  g.id = p_groupId AND g.client_id = p_clientId
    FOR    SHARE;
    IF NOT FOUND THEN
        RETURN -1;  -- -1 = no such group in this tenant
    END IF;
    IF v_system IS NOT NULL THEN
        RETURN -2;  -- -2 = a system group
    END IF;
    PERFORM 1 FROM tbl_users u
    WHERE  u.id = p_userId AND u.client_id = p_clientId AND u.deleted_at IS NULL;
    IF NOT FOUND THEN
        RETURN -3;  -- -3 = no such live user in this tenant
    END IF;

    INSERT INTO tbl_group_managers (group_id, client_id, user_id,
                                    appointed_by_user_id, appointed_by_owner_id)
    VALUES (p_groupId, p_clientId, p_userId, p_byUserId, p_byOwnerId)
    ON CONFLICT (group_id, user_id) DO NOTHING;
    GET DIAGNOSTICS v_added = ROW_COUNT;

    IF v_added > 0 THEN
        UPDATE tbl_users
        SET    admin_version = admin_version + 1
        WHERE  id = p_userId AND client_id = p_clientId;
    END IF;
    RETURN v_added;
END;
$$;
