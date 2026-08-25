/****** Object: Table-valued Function [udf_ListUserGroups] ******/
-- Group memberships for a PAGE of users in one round trip, avoiding a query
-- per row when rendering the user list.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_ListUserGroups(p_clientId TEXT, p_userIds TEXT[])
RETURNS SETOF vw_UserGroupMembership
LANGUAGE sql
STABLE
AS $$
    SELECT * FROM vw_UserGroupMembership v
    WHERE  v.client_id = p_clientId
      AND  v.user_id   = ANY(p_userIds)
    ORDER  BY v.group_name;
$$;
