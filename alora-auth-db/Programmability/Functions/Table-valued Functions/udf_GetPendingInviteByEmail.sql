/****** Object: Table-valued Function [udf_GetPendingInviteByEmail] ******/
-- Duplicate-invite guard: is an invitation already outstanding for this
-- address in this tenant? Prevents two independently redeemable tokens
-- existing at once.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_GetPendingInviteByEmail(p_clientId TEXT, p_email TEXT)
RETURNS SETOF vw_PendingInvitation
LANGUAGE sql
STABLE
AS $$
    SELECT * FROM vw_PendingInvitation v
    WHERE  v.client_id    = p_clientId
      AND  lower(v.email) = lower(p_email);
$$;
