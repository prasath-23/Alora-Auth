/****** Object: Table-valued Function [udf_GetLoginPolicy] ******/
-- One policy, tenant-scoped.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_GetLoginPolicy(p_policyId TEXT, p_clientId TEXT)
RETURNS SETOF tbl_login_policies
LANGUAGE sql
STABLE
AS $$
    SELECT * FROM tbl_login_policies lp WHERE lp.id = p_policyId AND lp.client_id = p_clientId;
$$;
