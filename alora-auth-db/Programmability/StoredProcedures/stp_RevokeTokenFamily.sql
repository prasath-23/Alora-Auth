/****** Object: Stored Procedure [stp_RevokeTokenFamily] ******/
-- THE reuse-detection response: burns a login, every product login under it
-- and all their live generations. Called when a spent refresh token is
-- replayed outside the grace window. The caller must COMMIT this before
-- returning the error -- if it is rolled back with the failing request, the
-- family is never actually revoked and the detection is cosmetic.
--
-- Implemented as a PROCEDURE: nothing needs to be returned, so the caller
-- invokes it with CALL.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE PROCEDURE stp_RevokeTokenFamily(p_familyId TEXT, p_reason TEXT DEFAULT 'REUSE_DETECTED')
LANGUAGE sql
AS $$
    UPDATE tbl_session_families
    SET    revoked_at     = now(),
           revoked_reason = p_reason::"SessionRevokedReason"
    WHERE  (id = p_familyId OR parent_family_id = p_familyId)
      AND  revoked_at IS NULL;
    UPDATE tbl_user_sessions
    SET    revoked_at     = now(),
           revoked_reason = p_reason::"SessionRevokedReason"
    WHERE  family_id IN (SELECT f.id FROM tbl_session_families f
                         WHERE  f.id = p_familyId OR f.parent_family_id = p_familyId)
      AND  revoked_at IS NULL;
$$;
