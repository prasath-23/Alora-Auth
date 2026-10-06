/****** Object: Stored Procedure [stp_DeleteLoginPolicy] ******/
-- Deletes a login policy. Never the default, and a policy still assigned to
-- a user or group is refused by its foreign keys (23503).
--
-- Implemented as a FUNCTION, not a PROCEDURE: the caller needs the result,
-- and PostgreSQL procedures cannot return a result set.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_DeleteLoginPolicy(p_policyId TEXT, p_clientId TEXT)
RETURNS INTEGER
LANGUAGE sql
VOLATILE
AS $$
    WITH del AS (
        DELETE FROM tbl_login_policies
        WHERE  id         = p_policyId
          AND  client_id  = p_clientId
          AND  is_default = false
        RETURNING 1
    )
    SELECT count(*)::int FROM del;
$$;
