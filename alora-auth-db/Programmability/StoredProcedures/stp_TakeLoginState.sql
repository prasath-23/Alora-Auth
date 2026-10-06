/****** Object: Stored Procedure [stp_TakeLoginState] ******/
-- Consumes a sign-in state: one atomic DELETE, so a state can be used once
-- and only before it expires.
--
-- Implemented as a FUNCTION, not a PROCEDURE: the caller needs the result,
-- and PostgreSQL procedures cannot return a result set.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_TakeLoginState(p_stateHash TEXT, p_kind "LoginStateKind")
RETURNS SETOF tbl_login_states
LANGUAGE sql
VOLATILE
AS $$
    DELETE FROM tbl_login_states
    WHERE  state_hash = p_stateHash
      AND  kind       = p_kind
      AND  expires_at > now()
    RETURNING *;
$$;
