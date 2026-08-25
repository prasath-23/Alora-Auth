/****** Object: Scalar-valued Function [udf_HasGroupFeature] ******/
-- TRUE when the user belongs to a group IN THIS TENANT that grants the
-- feature. The group's OWN client_id is checked, not just the membership
-- row: matching only the membership would let a group belonging to another
-- organisation confer permission here.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_HasGroupFeature(p_featureKey TEXT, p_clientId TEXT, p_userId TEXT)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM   tbl_group_features gf
        JOIN   tbl_groups        g  ON g.id  = gf.group_id
        JOIN   tbl_user_groups   ug ON ug.group_id = g.id
        WHERE  gf.feature_key = p_featureKey
          AND  g.client_id    = p_clientId
          AND  ug.user_id     = p_userId
    );
$$;
