/****** Object: Table-valued Function [udf_ListUserFeatures] ******/
-- Distinct feature keys the user holds through group membership, for the UI
-- to decide what to render.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_ListUserFeatures(p_clientId TEXT, p_userId TEXT)
RETURNS SETOF TEXT
LANGUAGE sql
STABLE
AS $$
    SELECT DISTINCT gf.feature_key
    FROM   tbl_group_features gf
    JOIN   tbl_groups      g  ON g.id = gf.group_id
    JOIN   tbl_user_groups ug ON ug.group_id = g.id AND ug.client_id = g.client_id
    WHERE  g.client_id = p_clientId
      AND  ug.user_id  = p_userId
    ORDER  BY gf.feature_key;
$$;
