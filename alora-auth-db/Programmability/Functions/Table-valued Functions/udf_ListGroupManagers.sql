/****** Object: Table-valued Function [udf_ListGroupManagers] ******/
-- A group's managers, tenant-scoped, by address.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_ListGroupManagers(p_groupId TEXT, p_clientId TEXT)
RETURNS SETOF vw_GroupManager
LANGUAGE sql
STABLE
AS $$
    SELECT * FROM vw_GroupManager v
    WHERE  v.group_id  = p_groupId
      AND  v.client_id = p_clientId
    ORDER  BY v.email;
$$;
