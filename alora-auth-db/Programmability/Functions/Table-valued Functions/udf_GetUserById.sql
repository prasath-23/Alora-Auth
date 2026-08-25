/****** Object: Table-valued Function [udf_GetUserById] ******/
-- Full row by primary key. NOT tenant-scoped and NOT soft-delete filtered
-- because the id comes from a verified JWT subject, making this a trusted
-- self-load. It is the only read that exposes password_hash outside the
-- login path, and it exists for the self-service change-password flow.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_GetUserById(p_userId TEXT)
RETURNS SETOF tbl_users
LANGUAGE sql
STABLE
AS $$
    SELECT * FROM tbl_users u WHERE u.id = p_userId;
$$;
