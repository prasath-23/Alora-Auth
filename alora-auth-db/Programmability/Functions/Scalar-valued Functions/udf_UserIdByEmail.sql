/****** Object: Scalar-valued Function [udf_UserIdByEmail] ******/
-- Resolves an address to a live user id WITHIN a tenant. Backs adding a
-- group member by email, which exists because managing groups does not imply
-- permission to list users.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_UserIdByEmail(p_clientId TEXT, p_email TEXT)
RETURNS TEXT
LANGUAGE sql
STABLE
AS $$
    SELECT u.id
    FROM   tbl_users u
    WHERE  u.client_id    = p_clientId
      AND  lower(u.email) = lower(p_email)
      AND  u.deleted_at  IS NULL;
$$;
