/****** Object: Scalar-valued Function [udf_ActiveEmailExists] ******/
-- TRUE when a live user already holds this address in the tenant. Used as a
-- pre-insert check so the caller can return a clean 409 instead of surfacing
-- a unique-violation as a 500. Case-insensitive, matching the unique index.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_ActiveEmailExists(p_clientId TEXT, p_email TEXT)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
AS $$
    SELECT EXISTS (
        SELECT 1 FROM tbl_users u
        WHERE  u.client_id    = p_clientId
          AND  lower(u.email) = lower(p_email)
          AND  u.deleted_at  IS NULL
    );
$$;
