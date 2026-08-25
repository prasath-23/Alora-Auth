/****** Object: Table-valued Function [udf_GetSessionByRefreshHashForUpdate] ******/
-- THE rotation lookup. Two deliberate properties:
--   * FOR UPDATE locks the row for the caller's transaction, so two concurrent rotations of the same token serialise instead of both minting a successor.
--   * There is NO revoked_at filter. A revoked match is precisely the signal that distinguishes a replayed token from an unknown one, and filtering it out would make reuse detection impossible.
-- VOLATILE because a STABLE function may not take row locks.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_GetSessionByRefreshHashForUpdate(p_tokenHash TEXT)
RETURNS SETOF tbl_user_sessions
LANGUAGE sql
VOLATILE
AS $$
    SELECT * FROM tbl_user_sessions s WHERE s.refresh_token_hash = p_tokenHash FOR UPDATE;
$$;
