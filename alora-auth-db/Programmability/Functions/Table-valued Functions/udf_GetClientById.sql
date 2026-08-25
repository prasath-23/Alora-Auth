/****** Object: Table-valued Function [udf_GetClientById] ******/
-- The tenant record. tbl_clients holds no credential, so the full row is
-- safe to return.
--
-- CREATE OR REPLACE so the build is idempotent.

CREATE OR REPLACE FUNCTION udf_GetClientById(p_clientId TEXT)
RETURNS SETOF tbl_clients
LANGUAGE sql
STABLE
AS $$
    SELECT * FROM tbl_clients c WHERE c.id = p_clientId;
$$;
