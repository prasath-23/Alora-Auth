/****** Object: Stored Procedure [stp_CreateGroup] ******/
-- Creates a group. A duplicate name within the tenant raises 23505 via the
-- case-insensitive unique index, which the caller maps to 409.
--
-- Implemented as a FUNCTION, not a PROCEDURE: the caller needs the result,
-- and PostgreSQL procedures cannot return a result set.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_CreateGroup(p_clientId TEXT, p_name TEXT, p_description TEXT)
RETURNS SETOF tbl_groups
LANGUAGE sql
VOLATILE
AS $$
    INSERT INTO tbl_groups (client_id, name, description)
    VALUES (p_clientId, p_name, p_description)
    RETURNING *;
$$;
