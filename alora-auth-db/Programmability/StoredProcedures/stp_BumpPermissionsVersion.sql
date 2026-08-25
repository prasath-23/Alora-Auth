/****** Object: Stored Procedure [stp_BumpPermissionsVersion] ******/
-- Invalidates the user's outstanding access tokens. The increment is done IN
-- SQL (pv = pv + 1) rather than read-modify-write, so concurrent grants
-- cannot lose an increment and leave a stale token valid.
--
-- Implemented as a PROCEDURE: nothing needs to be returned, so the caller
-- invokes it with CALL.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE PROCEDURE stp_BumpPermissionsVersion(p_userId TEXT, p_clientId TEXT)
LANGUAGE sql
AS $$
    UPDATE tbl_users
    SET    permissions_version = permissions_version + 1,
           updated_at          = now()
    WHERE  id        = p_userId
      AND  client_id = p_clientId;
$$;
