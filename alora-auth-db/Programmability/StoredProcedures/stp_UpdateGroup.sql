/****** Object: Stored Procedure [stp_UpdateGroup] ******/
-- Renames or re-describes a group, tenant-scoped. Zero rows means unknown or
-- another tenant's group.
--
-- Implemented as a FUNCTION, not a PROCEDURE: the caller needs the result,
-- and PostgreSQL procedures cannot return a result set.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_UpdateGroup(p_groupId TEXT, p_clientId TEXT, p_name TEXT, p_description TEXT)
RETURNS SETOF tbl_groups
LANGUAGE sql
VOLATILE
AS $$
    UPDATE tbl_groups
    SET    name        = p_name,
           description = p_description,
           updated_at  = now()
    WHERE  id        = p_groupId
      AND  client_id = p_clientId
    RETURNING *;
$$;
