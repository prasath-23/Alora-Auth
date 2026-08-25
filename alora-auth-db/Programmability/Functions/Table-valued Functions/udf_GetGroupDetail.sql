/****** Object: Table-valued Function [udf_GetGroupDetail] ******/
-- One row per member of a group, tenant-scoped.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_GetGroupDetail(p_groupId TEXT, p_clientId TEXT)
RETURNS SETOF vw_GroupDetailRow
LANGUAGE sql
STABLE
AS $$
    SELECT * FROM vw_GroupDetailRow v
    WHERE  v.id        = p_groupId
      AND  v.client_id = p_clientId
    ORDER  BY v.user_email NULLS LAST;
$$;
