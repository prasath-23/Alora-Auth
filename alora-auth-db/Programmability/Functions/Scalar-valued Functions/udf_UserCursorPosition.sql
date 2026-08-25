/****** Object: Scalar-valued Function [udf_UserCursorPosition] ******/
-- Translates an opaque page cursor (a user id) into its keyset position.
-- Tenant-scoped, so a cursor forged from another tenant's id resolves to
-- NULL rather than revealing a position in their list.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_UserCursorPosition(p_userId TEXT, p_clientId TEXT)
RETURNS TIMESTAMPTZ
LANGUAGE sql
STABLE
AS $$
    SELECT u.created_at
    FROM   tbl_users u
    WHERE  u.id        = p_userId
      AND  u.client_id = p_clientId
      AND  u.deleted_at IS NULL;
$$;
