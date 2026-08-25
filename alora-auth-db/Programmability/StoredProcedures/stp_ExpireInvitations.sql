/****** Object: Stored Procedure [stp_ExpireInvitations] ******/
-- Scheduled sweep moving lapsed invitations to EXPIRED. Batched to keep the
-- transaction short. Hygiene only: the pending view already filters on
-- expiry.
--
-- Implemented as a PROCEDURE: nothing needs to be returned, so the caller
-- invokes it with CALL.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE PROCEDURE stp_ExpireInvitations(p_batchSize INTEGER DEFAULT 500)
LANGUAGE sql
AS $$
    UPDATE tbl_invitations
    SET    status = 'EXPIRED'
    WHERE  id IN (
        SELECT i.id
        FROM   tbl_invitations i
        WHERE  i.expires_at < now()
          AND  i.status     = 'PENDING'
        LIMIT  p_batchSize
    );
$$;
