/****** Object: Table-valued Function [udf_ListManagedGroups] ******/
-- The groups a person manages in their tenant, as the group list shows them.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_ListManagedGroups(p_userId TEXT, p_clientId TEXT)
RETURNS SETOF vw_GroupListItem
LANGUAGE sql
STABLE
AS $$
    SELECT * FROM vw_GroupListItem v
    WHERE  v.client_id = p_clientId
      AND  EXISTS (SELECT 1 FROM tbl_group_managers gm
                   WHERE  gm.group_id  = v.id
                     AND  gm.client_id = v.client_id
                     AND  gm.user_id   = p_userId)
    ORDER  BY v.name;
$$;
