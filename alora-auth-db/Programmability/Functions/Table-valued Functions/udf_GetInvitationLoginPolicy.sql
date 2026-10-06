/****** Object: Table-valued Function [udf_GetInvitationLoginPolicy] ******/
-- The login policy an invited user will be under: the highest-priority
-- policy among the invited groups, else the tenant default. Lets the
-- acceptance page offer only the methods the user will actually be allowed.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_GetInvitationLoginPolicy(p_invitationId TEXT, p_clientId TEXT)
RETURNS SETOF tbl_login_policies
LANGUAGE sql
STABLE
AS $$
    SELECT lp.* FROM tbl_login_policies lp
    WHERE  lp.client_id = p_clientId
      AND  lp.id = COALESCE(
             (SELECT gp.id
              FROM   tbl_invitation_groups ig
              JOIN   tbl_groups         g  ON g.id  = ig.group_id
                                          AND g.client_id = ig.client_id
              JOIN   tbl_login_policies gp ON gp.id = g.login_policy_id
                                          AND gp.client_id = g.client_id
              WHERE  ig.invitation_id = p_invitationId
                AND  ig.client_id     = p_clientId
              ORDER  BY gp.priority DESC
              LIMIT  1),
             (SELECT d.id FROM tbl_login_policies d
              WHERE  d.client_id = p_clientId
                AND  d.is_default));
$$;
