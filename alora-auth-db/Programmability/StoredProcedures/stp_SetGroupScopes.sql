/****** Object: Stored Procedure [stp_SetGroupScopes] ******/
-- Replaces the App Central scopes a group gives its members, wholesale, so the
-- caller submits the complete desired state instead of computing a diff.
--
-- Tenant scoping is ENFORCED HERE rather than assumed: the group is looked up
-- by (id, tenant), so a group of another organisation changes nothing (-1).
-- A system group is refused (-3): the Admins group holds every scope by
-- definition and has none to set. An unknown scope, or an API client's scope,
-- fails the foreign key into tbl_scopes.
--
-- Every member's admin_version is bumped, in this same transaction: their login
-- tokens describe access they no longer have (or lack access they now have).
--
-- Implemented as a FUNCTION: the caller needs the outcome.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_SetGroupScopes(
    p_groupId  TEXT,
    p_clientId TEXT,
    p_scopes   TEXT[]
)
RETURNS INTEGER
LANGUAGE plpgsql
VOLATILE
AS $$
DECLARE
    v_found    BOOLEAN;
    v_system   TEXT;
    v_inserted INTEGER := 0;
BEGIN
    SELECT true, g.system_key INTO v_found, v_system
    FROM   tbl_groups g
    WHERE  g.id = p_groupId AND g.client_id = p_clientId
    FOR    UPDATE;

    IF v_found IS NULL THEN
        RETURN -1;  -- -1 = group not found in this tenant
    END IF;
    IF v_system IS NOT NULL THEN
        RETURN -3;  -- -3 = a system group, which holds every scope already
    END IF;

    DELETE FROM tbl_group_scopes WHERE group_id = p_groupId AND client_id = p_clientId;

    IF p_scopes IS NOT NULL AND cardinality(p_scopes) > 0 THEN
        INSERT INTO tbl_group_scopes (group_id, client_id, scope)
        SELECT DISTINCT p_groupId, p_clientId, s
        FROM   unnest(p_scopes) AS s;
        GET DIAGNOSTICS v_inserted = ROW_COUNT;
    END IF;

    UPDATE tbl_users u
    SET    admin_version = u.admin_version + 1
    FROM   tbl_user_groups ug
    WHERE  ug.group_id  = p_groupId
      AND  ug.client_id = p_clientId
      AND  u.id         = ug.user_id
      AND  u.client_id  = ug.client_id;

    RETURN v_inserted;  -- >= 0 = number of scopes the group now gives
END;
$$;
