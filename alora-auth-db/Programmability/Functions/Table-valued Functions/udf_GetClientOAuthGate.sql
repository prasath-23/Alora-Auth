/****** Object: Table-valued Function [udf_GetClientOAuthGate] ******/
-- The tenant's identity-provider policy, checked before a federated login is
-- allowed to proceed.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_GetClientOAuthGate(p_clientId TEXT)
RETURNS SETOF vw_ClientOAuthGate
LANGUAGE sql
STABLE
AS $$
    SELECT * FROM vw_ClientOAuthGate v WHERE v.id = p_clientId;
$$;
