/****** Object: Stored Procedure [stp_DeleteGroup] ******/
-- Deletes a group; its features and memberships cascade. Tenant-scoped, so a
-- foreign id deletes nothing.
--
-- Implemented as a FUNCTION, not a PROCEDURE: the caller needs the result,
-- and PostgreSQL procedures cannot return a result set.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_DeleteGroup(p_groupId TEXT, p_clientId TEXT)
RETURNS INTEGER
LANGUAGE sql
VOLATILE
AS $$
    WITH del AS (
        DELETE FROM tbl_groups
        WHERE  id        = p_groupId
          AND  client_id = p_clientId
        RETURNING 1
    )
    SELECT count(*)::int FROM del;
$$;
