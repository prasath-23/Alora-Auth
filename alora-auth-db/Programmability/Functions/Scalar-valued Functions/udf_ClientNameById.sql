/****** Object: Scalar-valued Function [udf_ClientNameById] ******/
-- The tenant's display name, for invitation emails.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_ClientNameById(p_clientId TEXT)
RETURNS TEXT
LANGUAGE sql
STABLE
AS $$
    SELECT c.name FROM tbl_clients c WHERE c.id = p_clientId;
$$;
