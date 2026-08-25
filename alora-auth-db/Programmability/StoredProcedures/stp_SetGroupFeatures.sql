/****** Object: Stored Procedure [stp_SetGroupFeatures] ******/
-- Replaces a group's feature keys wholesale, so the caller submits the complete
-- desired state instead of computing a diff.
--
-- Tenant scoping is ENFORCED HERE rather than assumed. tbl_group_features has no
-- client_id of its own, so ownership is re-derived through tbl_groups on both
-- statements: a group id belonging to another organisation therefore deletes and
-- inserts nothing, instead of silently rewriting their permissions.
--
-- Implemented as a FUNCTION because the caller needs the inserted count to tell
-- "wrong tenant" from "no features requested".
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_SetGroupFeatures(
    p_groupId     TEXT,
    p_clientId    TEXT,
    p_featureKeys TEXT[]
)
RETURNS INTEGER
LANGUAGE plpgsql
VOLATILE
AS $$
DECLARE
    v_owned    BOOLEAN;
    v_inserted INTEGER := 0;
BEGIN
    SELECT EXISTS (
        SELECT 1 FROM tbl_groups g
        WHERE  g.id = p_groupId AND g.client_id = p_clientId
    ) INTO v_owned;

    IF NOT v_owned THEN
        RETURN -1;  -- -1 = group not found in this tenant
    END IF;

    DELETE FROM tbl_group_features WHERE group_id = p_groupId;

    IF p_featureKeys IS NOT NULL AND array_length(p_featureKeys, 1) > 0 THEN
        INSERT INTO tbl_group_features (group_id, feature_key)
        SELECT p_groupId, k
        FROM   unnest(p_featureKeys) AS k;

        v_inserted := array_length(p_featureKeys, 1);
    END IF;

    RETURN v_inserted;  -- >= 0 = number of feature keys now attached
END;
$$;
