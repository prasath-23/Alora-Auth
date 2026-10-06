/****** Object: Scalar-valued Function [udf_IsGroupManager] ******/
-- TRUE when the user manages the group, in that tenant. The manager door
-- asks it on every request; its writes ask again inside the procedure, at
-- the moment of the change.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_IsGroupManager(p_groupId TEXT, p_clientId TEXT, p_userId TEXT)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
AS $$
    SELECT EXISTS (
        SELECT 1 FROM tbl_group_managers gm
        WHERE  gm.group_id  = p_groupId
          AND  gm.client_id = p_clientId
          AND  gm.user_id   = p_userId
    );
$$;
