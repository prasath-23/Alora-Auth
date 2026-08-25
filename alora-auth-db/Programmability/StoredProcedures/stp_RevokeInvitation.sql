/****** Object: Stored Procedure [stp_RevokeInvitation] ******/
-- Cancels a pending invitation. Guarded on status = 'PENDING' so an already
-- accepted or revoked invitation is not silently re-stamped, and
-- tenant-scoped so a foreign id affects nothing and reports 404.
--
-- Implemented as a FUNCTION, not a PROCEDURE: the caller needs the result,
-- and PostgreSQL procedures cannot return a result set.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_RevokeInvitation(p_invitationId TEXT, p_clientId TEXT, p_revokedByUserId TEXT)
RETURNS INTEGER
LANGUAGE sql
VOLATILE
AS $$
    WITH upd AS (
        UPDATE tbl_invitations
        SET    status             = 'REVOKED',
               revoked_at         = now(),
               revoked_by_user_id = p_revokedByUserId,
               updated_at         = now()
        WHERE  id        = p_invitationId
          AND  client_id = p_clientId
          AND  status    = 'PENDING'
        RETURNING 1
    )
    SELECT count(*)::int FROM upd;
$$;
