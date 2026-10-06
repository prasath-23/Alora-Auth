/****** Object: Table-valued Function [udf_ListLoginPolicies] ******/
-- A tenant's login policies, highest priority first.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_ListLoginPolicies(p_clientId TEXT)
RETURNS SETOF tbl_login_policies
LANGUAGE sql
STABLE
AS $$
    SELECT * FROM tbl_login_policies lp WHERE lp.client_id = p_clientId ORDER BY lp.priority DESC;
$$;
