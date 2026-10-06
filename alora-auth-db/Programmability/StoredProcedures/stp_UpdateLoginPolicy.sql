/****** Object: Stored Procedure [stp_UpdateLoginPolicy] ******/
-- Updates a login policy, tenant-scoped.
--
-- Implemented as a FUNCTION, not a PROCEDURE: the caller needs the result,
-- and PostgreSQL procedures cannot return a result set.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_UpdateLoginPolicy(p_policyId TEXT, p_clientId TEXT, p_name TEXT, p_allowPassword BOOLEAN, p_allowGoogle BOOLEAN, p_ssoConnectionId TEXT, p_priority INTEGER)
RETURNS SETOF tbl_login_policies
LANGUAGE sql
VOLATILE
AS $$
    UPDATE tbl_login_policies
    SET    name              = p_name,
           allow_password    = p_allowPassword,
           allow_google      = p_allowGoogle,
           sso_connection_id = p_ssoConnectionId,
           priority          = p_priority,
           updated_at        = now()
    WHERE  id        = p_policyId
      AND  client_id = p_clientId
    RETURNING *;
$$;
