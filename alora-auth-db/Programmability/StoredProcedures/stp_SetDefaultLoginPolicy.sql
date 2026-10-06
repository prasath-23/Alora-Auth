/****** Object: Stored Procedure [stp_SetDefaultLoginPolicy] ******/
-- Makes a policy its tenant's default. The old default is cleared first, in the
-- same transaction, so the one-default-per-tenant unique index is never violated
-- even transiently. Returns 0 for a policy outside the tenant.
--
-- Implemented as a FUNCTION: the caller needs the outcome.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION stp_SetDefaultLoginPolicy(
    p_policyId TEXT,
    p_clientId TEXT
)
RETURNS INTEGER
LANGUAGE plpgsql
VOLATILE
AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM tbl_login_policies
                   WHERE  id = p_policyId AND client_id = p_clientId) THEN
        RETURN 0;
    END IF;

    UPDATE tbl_login_policies
    SET    is_default = false, updated_at = now()
    WHERE  client_id = p_clientId AND is_default AND id <> p_policyId;

    UPDATE tbl_login_policies
    SET    is_default = true, updated_at = now()
    WHERE  id = p_policyId AND client_id = p_clientId;

    RETURN 1;
END;
$$;
