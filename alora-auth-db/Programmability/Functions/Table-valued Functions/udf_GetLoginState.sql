/****** Object: Table-valued Function [udf_GetLoginState] ******/
-- A live sign-in state by its hash, WITHOUT consuming it: the account
-- chooser reads its candidates before the choice is made. Redemption is
-- always stp_TakeLoginState, which deletes the row in the same statement.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_GetLoginState(p_stateHash TEXT, p_kind "LoginStateKind")
RETURNS SETOF tbl_login_states
LANGUAGE sql
STABLE
AS $$
    SELECT * FROM tbl_login_states s
    WHERE  s.state_hash = p_stateHash
      AND  s.kind       = p_kind
      AND  s.expires_at > now();
$$;
