/****** Object: Table-valued Function [udf_GetPendingInvitation] ******/
-- Looks a redeemable invitation up by its at-rest hash. The view supplies
-- the pending, unexpired and active-tenant predicates, so every caller
-- inherits them and none can accidentally honour a dead invitation.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_GetPendingInvitation(p_tokenHash TEXT)
RETURNS SETOF vw_PendingInvitation
LANGUAGE sql
STABLE
AS $$
    SELECT * FROM vw_PendingInvitation v WHERE v.token_hash = p_tokenHash;
$$;
