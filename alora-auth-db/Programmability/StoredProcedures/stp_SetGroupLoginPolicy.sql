/****** Object: Stored Procedure [stp_SetGroupLoginPolicy] ******/
-- Assigns a group a login policy, or clears it with NULL. The composite key
-- refuses another tenant's policy.
--
-- Implemented as a FUNCTION, not a PROCEDURE: the caller needs the result,
-- and PostgreSQL procedures cannot return a result set.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_SetGroupLoginPolicy(p_groupId TEXT, p_clientId TEXT, p_policyId TEXT)
RETURNS INTEGER
LANGUAGE sql
VOLATILE
AS $$
    WITH upd AS (
        UPDATE tbl_groups
        SET    login_policy_id = p_policyId,
               updated_at      = now()
        WHERE  id        = p_groupId
          AND  client_id = p_clientId
        RETURNING 1
    )
    SELECT count(*)::int FROM upd;
$$;
