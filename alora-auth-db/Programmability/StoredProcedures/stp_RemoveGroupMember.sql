/****** Object: Stored Procedure [stp_RemoveGroupMember] ******/
-- Removes a member. Scoped by all three columns so a foreign group id
-- removes nothing.
--
-- Implemented as a FUNCTION, not a PROCEDURE: the caller needs the result,
-- and PostgreSQL procedures cannot return a result set.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_RemoveGroupMember(p_userId TEXT, p_groupId TEXT, p_clientId TEXT)
RETURNS INTEGER
LANGUAGE sql
VOLATILE
AS $$
    WITH del AS (
        DELETE FROM tbl_user_groups
        WHERE  user_id   = p_userId
          AND  group_id  = p_groupId
          AND  client_id = p_clientId
        RETURNING 1
    )
    SELECT count(*)::int FROM del;
$$;
