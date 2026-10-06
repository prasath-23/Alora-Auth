/****** Object: Stored Procedure [stp_CreateLoginPolicy] ******/
-- Creates a (non-default) login policy. A duplicate name or priority raises
-- 23505; a policy allowing no method is refused by its CHECK.
--
-- Implemented as a FUNCTION, not a PROCEDURE: the caller needs the result,
-- and PostgreSQL procedures cannot return a result set.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_CreateLoginPolicy(p_clientId TEXT, p_name TEXT, p_allowPassword BOOLEAN, p_allowGoogle BOOLEAN, p_ssoConnectionId TEXT, p_priority INTEGER)
RETURNS SETOF tbl_login_policies
LANGUAGE sql
VOLATILE
AS $$
    INSERT INTO tbl_login_policies (client_id, name, allow_password, allow_google,
                                    sso_connection_id, priority)
    VALUES (p_clientId, p_name, p_allowPassword, p_allowGoogle, p_ssoConnectionId, p_priority)
    RETURNING *;
$$;
