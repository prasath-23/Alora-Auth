/****** Object: Stored Procedure [stp_SoftDeleteUser] ******/
-- Soft delete. Stamping deleted_at drops the row out of the partial unique
-- index on email, which is what frees the address for re-invitation while
-- keeping the row for the audit trail.
--
-- Implemented as a PROCEDURE: nothing needs to be returned, so the caller
-- invokes it with CALL.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE PROCEDURE stp_SoftDeleteUser(p_userId TEXT, p_clientId TEXT)
LANGUAGE sql
AS $$
    UPDATE tbl_users
    SET    deleted_at = now(),
           updated_at = now()
    WHERE  id        = p_userId
      AND  client_id = p_clientId;
$$;
