/****** Object: View [vw_PendingInvitation] ******/
-- A redeemable invitation: PENDING, unexpired, and belonging to an ACTIVE
-- tenant. The tenant check is the kill switch -- a suspended organisation
-- must not keep onboarding members through invitations issued before
-- suspension.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE VIEW vw_PendingInvitation AS
SELECT i.id,
       i.email,
       i.client_id,
       i.invited_by_user_id,
       i.invited_by_owner_id,
       i.token_hash,
       i.expires_at,
       c.name AS client_name
FROM   tbl_invitations i
JOIN   tbl_clients c ON c.id = i.client_id
                    AND c.is_active = true
WHERE  i.status      = 'PENDING'
  AND  i.expires_at  > now();
